#!/usr/bin/env python3
"""auditooor-universal-action-classifier.py

Universal PreToolUse action classifier for the auditooor enforcement
infrastructure. Reads a PreToolUse JSON payload on stdin and emits a
structured classification on stdout describing:

  - action_signature       : a stable, low-cardinality string identifying
                             the action class (e.g. "Bash<git-commit>",
                             "Edit<submissions-draft>")
  - filepath_class         : where the action lands in the workspace
                             taxonomy (workspace-local / draft-file /
                             tracker-file / workspace-ledger / tools-py
                             / cwd-out-of-tree / etc).
  - required_rule_citations: list of rule IDs (R14, R36, R55, L34, ...)
                             whose citation the universal hook must
                             observe in the action's context to allow it.
  - exception_marker_required: bool. If true, the action either cites
                             the rules OR carries a rebuttal marker.
  - context_signals        : a flat dict of structured signals the
                             universal hook can grep for in the
                             surrounding context (prompt body, env vars,
                             recent log entries).
  - techupgrades           : list of capability-gap notes for things the
                             classifier cannot reliably classify from
                             a PreToolUse-only payload (capability gaps
                             the operator should know about).

Design contract
---------------
* Stdin: the verbatim PreToolUse JSON Anthropic sends to a hook.
* Stdout: a single JSON object matching the schema
  ``auditooor.universal_action_classification.v1``.
* Exit code 0 on success (even when classification yields a deny). The
  consuming shell hook owns the allow/deny decision; this tool only
  classifies. Exit code 1 is reserved for fatal classifier bugs (e.g.
  malformed JSON the classifier cannot recover from).

Scope of classification (initial seed; extends as
``action_to_rule_mapping`` matrix lands from the sibling ENFORCEMENT-
AUDIT lane). The classifier ships with the following wired classes.

r36-rebuttal: lane-GAP-FIX-3-C tools/agent-pathspec-register.py declared 5 files at lane start

  1. Bash<git-commit-without-context-pack-id> -> R36 / context-pack
  2. Bash<git-push-without-mcp-token>         -> R36 / MCP token
  3. Bash<git-destructive-op>                 -> R55
  4. Edit/Write/MultiEdit<submissions-draft-file>      -> L34
  5. Write<tools-py>                                   -> R36
  6. Agent<severity-decision-context>                  -> R14
  7. Agent<drill-class-lane>                           -> hacker MCP suite
  8. Bash<draft-file-write-via-shell>         -> L34 (Gap #56 closer)
  9. NotebookEdit<draft-file-write-via-cell>  -> L34 (Gap #57 closer)
 10. NotebookEdit<*>                          -> L34/R36 via _classify_filepath

Anything else falls through to ``action_signature: "<allow-by-default>"``
with empty required_rule_citations. The universal hook then permits the
call unconditionally.

Fail-open posture
-----------------
The classifier is conservative: when it cannot positively identify a
rule citation requirement, it emits empty required_rule_citations and
the universal hook allows the action. Block-decisions arise ONLY from
positive matches. The fail-open posture mirrors auditooor-mcp-first-
enforce.sh and prevents this hook from breaking unrelated dev work.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any

SCHEMA = "auditooor.universal_action_classification.v1"

# ---------------------------------------------------------------------------
# Path classification helpers
# ---------------------------------------------------------------------------

_DRAFT_STATUS_DIRS = {
    "staging", "ready", "filed", "packaged", "_killed", "_oos_rejected",
    "paste_ready", "held", "superseded",
}
_TRACKER_STEMS = {"SUBMISSIONS", "README", "TRACKER", "INDEX"}

# R36 pathspec-register.py call site:
#   python3 tools/agent-pathspec-register.py register \
#     --lane lane-ENFORCEMENT-PHASE-1-TIER-A-6-EXTREME-GAPS-CLOSURE \
#     --files tools/hooks/auditooor-universal-rule-enforce.sh,...
# (see lane brief for full pathspec list).

_DESTRUCTIVE_GIT_RE = re.compile(
    r"""
    \bgit\s+
    (?:
        reset\s+--(?:hard|merge|keep)\b
      | checkout\s+--\s
      | checkout\s+\S+\s*$
      | clean\s+-f(?:d)?\b
      | stash\s+drop\b
      | branch\s+-D\b
      | push\s+(?:.*\s)?-f\b
      | push\s+(?:.*\s)?--force\b
    )
    """,
    re.VERBOSE,
)

_GIT_COMMIT_RE = re.compile(r"\bgit\s+commit\b")
_GIT_PUSH_RE = re.compile(r"\bgit\s+push\b")
_MAKE_AUDIT_RE = re.compile(r"\bmake\s+(audit|audit-deep|audit-fast|hunt|fresh-audit)\b")

# ---------------------------------------------------------------------------
# Phase 1 Tier-A EXTREME-gap detection patterns (6 operator-incident anchored)
# ---------------------------------------------------------------------------
# Each pattern triggers a distinct DENY message and accepts a distinct
# override (per-rule env var AND/OR embedded rebuttal marker in the shell
# `# extreme-rebuttal-<gap-id>: <reason>` syntax).
#
# Spec: reports/v3_iter_2026-05-26/lane_ENFORCEMENT_AUDIT/phase1_extension_recommendations.md
# Lane: ENFORCEMENT-PHASE-1-TIER-A-6-EXTREME-GAPS-CLOSURE

# Gap 1: --no-verify on any git operation. NEVER-SKIP-HOOKS.
# Without this every other rule defeated by silent skip.
_NO_VERIFY_RE = re.compile(r"\bgit\b[^\n]*\s--no-verify\b")

# Gap 2: git push -f / --force to main/master/HEAD. NEVER-FORCE-PUSH-MAIN.
# Destroys reflog + MCP token state on origin/main.
_FORCE_PUSH_MAIN_RE = re.compile(
    r"\bgit\s+push\b[^\n]*(?:-f\b|--force\b|--force-with-lease\b)[^\n]*\b(?:origin[/ ])?(?:main|master|HEAD)\b"
    r"|\bgit\s+push\b[^\n]*\b(?:origin[/ ])?(?:main|master|HEAD)\b[^\n]*(?:-f\b|--force\b|--force-with-lease\b)",
    re.IGNORECASE,
)

# r36-rebuttal: pathspec lane-ENFORCEMENT-PHASE-1-TIER-A registered via tools/agent-pathspec-register.py
# Gap 3: git config WRITE operation. CLAUDE.md hard rule: never modify
# git config. Read operations (--get, --list, --get-all, --get-regexp,
# --show-*, -l, -e/--edit) are allowed.
#
# Detection logic (read-first short-circuit + 4-rule write detect):
#   1. Skip if the command body contains an explicit read flag.
#   2. Otherwise match either:
#      (a) a write-scope flag (--global / --system / --local / --worktree)
#      (b) a write-action flag (--add / --unset / --unset-all / --replace-all)
#      (c) a bare KEY=VALUE assignment
#      (d) two positional args after `git config` (KEY VALUE form)
_GIT_CONFIG_READ_FLAGS_RE = re.compile(
    r"\bgit\s+config\b[^\n]*\s(?:--get|--get-all|--get-regexp|--get-urlmatch|--list|--show-origin|--show-scope|-l|-e|--edit)\b"
)
_GIT_CONFIG_WRITE_SCOPE_FLAG_RE = re.compile(
    r"\bgit\s+config\b[^\n]*\s(?:--global|--system|--local|--worktree)\b"
)
_GIT_CONFIG_WRITE_ACTION_FLAG_RE = re.compile(
    r"\bgit\s+config\b[^\n]*\s(?:--add|--unset|--unset-all|--replace-all)\b"
)
_GIT_CONFIG_KEYVALUE_RE = re.compile(r"\bgit\s+config\b[^\n]*\s\S+=\S+")


def _is_git_config_write(command: str) -> bool:
    """Return True iff command is a git config WRITE op (not a read).

    A read op (--get / --list / --show-* / -l / -e) always passes.
    A write op is signalled by a write-scope flag, a write-action flag,
    a KEY=VALUE assignment, or KEY VALUE positional form.
    """
    if _GIT_CONFIG_READ_FLAGS_RE.search(command):
        return False
    if _GIT_CONFIG_WRITE_SCOPE_FLAG_RE.search(command):
        return True
    if _GIT_CONFIG_WRITE_ACTION_FLAG_RE.search(command):
        return True
    if _GIT_CONFIG_KEYVALUE_RE.search(command):
        return True
    # Positional KEY VALUE form: `git config user.email foo@bar.com`
    m = re.search(
        r"\bgit\s+config\s+([a-zA-Z][a-zA-Z0-9_.-]+)\s+(\S+)(?:\s|$)",
        command,
    )
    if m and not m.group(2).startswith("-"):
        return True
    return False

# Gap 4: gh gist delete. NEVER-DELETE-GISTS per memory anchor.
# Use clone + orphan branch + force-push to wipe revisions while
# preserving the URL.
_GIST_DELETE_RE = re.compile(r"\bgh\s+gist\s+delete\b")

# Gap 5: incrementNonce on polymarket wallet. wallet1 + wallet2 ALREADY
# BANNED per polymarket CLAUDE.md - this single call bans wallet3 too.
_INCREMENT_NONCE_RE = re.compile(r"\bincrementNonce\b", re.IGNORECASE)

# Gap 6: git reset --hard NOT via the wrapper script. R55 - iter17 OOOOO
# lane wiped 7 brief edits. Wrapper at tools/git-hooks/git-reset-safe.sh.
# If the command body invokes the wrapper script (anywhere), we treat it
# as the safe path and let R55 enforcement happen inside the wrapper.
_RAW_GIT_RESET_HARD_RE = re.compile(r"\bgit\s+reset\s+--hard\b")
_GIT_RESET_SAFE_WRAPPER_RE = re.compile(
    r"\btools/git-hooks/git-reset-safe\.sh\b"
    r"|\bgit-reset-safe\.sh\b",
)

# r36-rebuttal: lane LIFT-22-R55-REGEX-TIGHTEN registered via tools/agent-pathspec-register.py at lane start
# LIFT-22 (R55 regex tighten, 2026-05-26): false-positive carve-outs for
# inert contexts AND false-negative coverage for subprocess list form.
#
# LIFT-20 enforcement audit identified 4 FP patterns and 1 FN pattern that
# composed to manufacture the 20:56 940-record loss:
#   FP-1 grep "git reset --hard" file.txt       -> string-literal inside grep
#   FP-2 # example: git reset --hard would wipe -> bash comment
#   FP-3 echo "DO NOT run git reset --hard"     -> echo'd operator doc
#   FP-4 cat <<EOF ... git reset --hard ... EOF -> heredoc documentation
#         + Python """docstring with git reset --hard"""
#   FN-1 subprocess.run(["git","reset","--hard"]) -> Python list form
#         (commas break the \bgit\s+reset\s+--hard\b word boundary).
#
# Design: classify destructiveness by FIRST stripping the inert contexts
# from the command body (via _strip_inert_bash_contexts), THEN running the
# existing _RAW_GIT_RESET_HARD_RE / _DESTRUCTIVE_GIT_RE patterns. This
# keeps the TRUE-POSITIVE detection vocabulary unchanged while removing
# the 4 FP classes. A separate _SUBPROCESS_GIT_DESTRUCT_RE catches the FN
# class on the ORIGINAL command body (not the stripped form, because the
# subprocess.* call site is the load-bearing signal even when its arg list
# would otherwise look like an inert literal-list to the stripper).
#
# TRUE-POSITIVE conditions (after strip):
#   - `git reset --hard|--merge|--keep`
#   - `git checkout -- <path>`  / `git checkout <branch>` at line end
#   - `git clean -f` / `git clean -fd`
#   - `git stash drop`
#   - `git branch -D`
#   - `git push --force` / `-f`
# Also TRUE-POSITIVE (no strip required):
#   - subprocess.{run,call,check_call,check_output,Popen}(
#       [..., "git", "(reset|checkout|clean|stash|branch|push)", ...])
#   - os.system("git (reset|checkout|clean|stash|branch|push) ...")
#   - eval / exec / sh -c shell-exec wrappers around the same.
#
# FP-EXCLUSION classes (removed by the inert-context strip):
#   - bash comments (# ...)
#   - echo/printf/cat heredoc literal documentation
#   - grep / fgrep / rg / egrep first-arg pattern strings
#   - Python triple-quoted docstrings
#   - test-fixture string-list constants (R55_TEST_CASES = [...]) when
#     the surrounding source has no subprocess.* call.
#
# Empirical anchor: LIFT-20 enforcement audit
# (reports/v3_iter_2026-05-26/lane_LIFT_20*) confirmed the 4 FPs +
# 1 FN combined to manufacture the 940-record loss at 20:56.

# Subprocess-list-form catcher (FN-1 fix). Matches subprocess.{run,
# call, check_call, check_output, Popen}([..., "git",
# "(reset|checkout|clean|stash|branch|push)", ...]) plus the os.exec*
# family and bare check_output / getoutput in Python.
_SUBPROCESS_GIT_DESTRUCT_RE = re.compile(
    r"""
    (?:
        subprocess\.(?:run|call|check_call|check_output|Popen)
      | os\.exec(?:l|le|lp|lpe|v|ve|vp|vpe)
      | (?<![A-Za-z_])(?:check_output|getoutput)
    )
    \s*\(\s*
    \[
    [^]]*?
    ['"]git['"]
    \s*,\s*
    ['"](?:reset|checkout|clean|stash|branch|push)['"]
    """,
    re.VERBOSE | re.DOTALL,
)

# String-form catcher: os.system("git reset ..."), eval / exec / sh -c
# wrappers. Matches the exec invocation immediately followed by a quoted
# string that itself contains a destructive git op.
_STRING_SHELL_GIT_DESTRUCT_RE = re.compile(
    r"""
    (?:
        os\.system
      | os\.popen
      | (?:^|[\s;|&])(?:sh|bash|zsh|dash)\s+-c
      | (?<![A-Za-z_])eval
      | (?<![A-Za-z_])exec
    )
    \s*\(?\s*['"]\s*
    git\s+
    (?:
        reset\s+--(?:hard|merge|keep)
      | checkout\s+--
      | clean\s+-f
      | stash\s+drop
      | branch\s+-D
      | push\s+(?:[^"'\n]*\s)?(?:-f|--force)
    )
    """,
    re.VERBOSE,
)


# Inert-context strip helpers. Each takes a `str` and returns a `str` with
# the matching ranges replaced by spaces (preserves offsets so other
# regex offsets remain meaningful in error messages).

# Bash comment: # to EOL. Conservative - only when # starts a token
# (preceded by start-of-line, semicolon, pipe, ampersand, or whitespace).
_BASH_COMMENT_RE = re.compile(
    r"(?m)(?:^|(?<=[\s;|&]))#[^\n]*"
)

# Python triple-quoted docstring (both """ and '''). DOTALL so multi-line.
_PY_DOCSTRING_RE = re.compile(
    r'("""[^"]*?"""|\'\'\'[^\']*?\'\'\')',
    re.DOTALL,
)

# echo / printf first-arg quoted string. The arg may use single or double
# quotes; we strip the quoted body so a literal `git reset --hard` inside
# `echo "..."` no longer triggers the destructive-op regex.
_ECHO_STRING_RE = re.compile(
    r"""
    \b(?:echo|printf)\s+
    (?:
        "([^"\\]*(?:\\.[^"\\]*)*)"
      | '([^'\\]*(?:\\.[^'\\]*)*)'
    )
    """,
    re.VERBOSE,
)

# grep / rg / fgrep / egrep first-arg pattern - the QUOTED arg right
# after the command. We strip only the quoted body.
_GREP_PATTERN_RE = re.compile(
    r"""
    \b(?:grep|egrep|fgrep|rg|ripgrep)\s+
    (?:-[a-zA-Z0-9-]+\s+)*           # optional flags
    (?:
        "([^"\\]*(?:\\.[^"\\]*)*)"
      | '([^'\\]*(?:\\.[^'\\]*)*)'
    )
    """,
    re.VERBOSE,
)

# Heredoc bodies: cat <<EOF ... EOF (and -<<EOF, <<-EOF, <<'EOF' variants).
# We strip everything between the opening <<TAG marker and the line
# containing only TAG. Limited safety: only the first heredoc on a line.
_HEREDOC_RE = re.compile(
    r"""
    <<\s*-?\s*['"]?(?P<tag>[A-Za-z_][A-Za-z0-9_]*)['"]?[^\n]*\n
    (?P<body>.*?)
    \n[ \t]*(?P=tag)\b
    """,
    re.VERBOSE | re.DOTALL,
)

# Test-data list contexts. A bash command body that mentions a Python
# variable assignment to a literal list of destructive op strings (e.g.
# `R55_TEST_CASES = ["git reset --hard", ...]`) is NOT itself a
# destructive op. We strip the list literal IF AND ONLY IF the command
# body contains no subprocess.*/os.system/sh -c invocation that could
# consume the list.
_TEST_DATA_LIST_RE = re.compile(
    r"""
    \[
    \s*(?:['"][^'"]*['"]\s*,?\s*)+
    \]
    """,
    re.VERBOSE,
)


def _strip_inert_bash_contexts(command: str) -> str:
    """Return command with inert string contexts blanked out.

    Strips bash comments, echo/printf quoted args, grep/rg quoted patterns,
    heredoc bodies, Python triple-quoted docstrings, and pure test-data
    list literals (only when the surrounding command has no subprocess /
    os.system / shell-exec invocation that could consume them).

    The strip replaces each matched span with the same length of spaces
    so character offsets in the original command stay meaningful for
    diagnostics. This is critical because the destructive-op regex runs
    against the stripped form; if we collapsed lengths we would corrupt
    any byte-offset that flows into the diagnostic.
    """

    def _blank(match: "re.Match[str]") -> str:
        # Replace the WHOLE match (including the wrapping echo/grep/heredoc
        # delimiters) with spaces of the same length. This is the cheapest
        # way to keep offsets meaningful.
        return " " * (match.end() - match.start())

    stripped = command
    # 1. Bash comments (single-line, # to EOL).
    stripped = _BASH_COMMENT_RE.sub(_blank, stripped)
    # 2. Heredoc bodies (multi-line, between <<TAG and TAG).
    stripped = _HEREDOC_RE.sub(_blank, stripped)
    # 3. echo/printf quoted args.
    stripped = _ECHO_STRING_RE.sub(_blank, stripped)
    # 4. grep/rg/fgrep/egrep quoted patterns.
    stripped = _GREP_PATTERN_RE.sub(_blank, stripped)
    # 5. Python triple-quoted docstrings.
    stripped = _PY_DOCSTRING_RE.sub(_blank, stripped)
    # 6. Test-data list literals - only when NO subprocess/exec call site
    #    is present elsewhere in the body. If a subprocess.* call IS
    #    present, the _SUBPROCESS_GIT_DESTRUCT_RE is the right detector;
    #    we must NOT strip the list because then the subprocess detector
    #    would miss it too.
    if not (
        _SUBPROCESS_GIT_DESTRUCT_RE.search(stripped)
        or _STRING_SHELL_GIT_DESTRUCT_RE.search(stripped)
    ):
        stripped = _TEST_DATA_LIST_RE.sub(_blank, stripped)
    return stripped


def _is_destructive_git_op(command: str) -> tuple[bool, str]:
    """Classify a Bash command body for R55 destructive-git-op shape.

    Returns ``(is_destructive, source)`` where ``source`` is one of:
      - ``"raw-reset-hard"`` (Gap 6, EXTREME): raw ``git reset --hard``
        not routed through the wrapper script. The caller should emit
        the Gap-6 R55-FOREGROUND diagnostic.
      - ``"generic-destructive"``: any other destructive git op caught
        by ``_DESTRUCTIVE_GIT_RE``.
      - ``"subprocess-list"``: subprocess list-form catch (FN-1 fix).
      - ``"string-shell"``: os.system / sh -c string-form catch.
      - ``""``: not destructive.

    The function applies the inert-context strip before running the
    permissive regex, which removes the 4 FP classes documented above.
    """
    stripped = _strip_inert_bash_contexts(command)
    # Raw `git reset --hard` (Gap 6, EXTREME-class diagnostic).
    if (
        _RAW_GIT_RESET_HARD_RE.search(stripped)
        and not _GIT_RESET_SAFE_WRAPPER_RE.search(command)
    ):
        return True, "raw-reset-hard"
    if _DESTRUCTIVE_GIT_RE.search(stripped):
        return True, "generic-destructive"
    # Subprocess list-form FN catch (operates on the ORIGINAL command).
    if _SUBPROCESS_GIT_DESTRUCT_RE.search(command):
        return True, "subprocess-list"
    if _STRING_SHELL_GIT_DESTRUCT_RE.search(command):
        return True, "string-shell"
    return False, ""

# r36-rebuttal: lane-GAP-FIX-3-C declared in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py at lane start

# ---------------------------------------------------------------------------
# Gap #56: Bash shell-write draft bypass detection.
#
# ENFORCEMENT-COMPLETENESS-AUDIT (reports/v3_iter_2026-05-26_enforcement_audit
# /lane_ENFORCEMENT_COMPLETENESS_AUDIT/results.md, Gap #51 in audit numbering)
# identified this surface: the universal classifier inspects file_path on
# Write/Edit/MultiEdit, but Bash command bodies that write to draft files via
# shell redirects / sed -i / awk in-place / cp / mv / heredoc / inline-python
# silently pass as `Bash<other>` without L34 enforcement.
#
# Detection contract: a `Bash<draft-file-write-via-shell>` signature fires
# when any of the following draft-write shapes targets a path matching the
# L34 draft-file taxonomy (submissions/<status>/<slug>/<file>).
# ---------------------------------------------------------------------------

# Draft-path pattern: submissions/<status>/<slug>/<file> OR legacy
# submissions/<status>/<flat>.md
# Matches the same path classification as _classify_filepath().
_DRAFT_PATH_INSIDE = (
    r"submissions/"
    r"(?:staging|ready|filed|packaged|_killed|_oos_rejected|paste_ready|held|superseded)"
    r"/[^\s'\"<>;|&]+"
)
# Anchor either with absolute path leading directory or workspace-relative
_DRAFT_PATH_RE = re.compile(_DRAFT_PATH_INSIDE)

# Shape 1: stdout redirect to a draft path: `... > path` or `... >> path`
# Handles heredoc shape `cat <<EOF > path`, `cat <<'EOF' >> path`, `echo > path`, etc.
_SHELL_REDIRECT_TO_DRAFT_RE = re.compile(
    rf">>?\s*['\"]?(?:[^'\"\s|;&]*/)?{_DRAFT_PATH_INSIDE}",
)

# Shape 2: tee / tee -a writing to draft path
_TEE_TO_DRAFT_RE = re.compile(
    rf"\btee\b(?:\s+-[a-zA-Z]+)*\s+['\"]?(?:[^'\"\s|;&]*/)?{_DRAFT_PATH_INSIDE}",
)

# Shape 3: sed -i / sed -i '' against a draft path
_SED_INPLACE_DRAFT_RE = re.compile(
    rf"\bsed\b[^|;&\n]*?\s-i(?:\s*'[^']*')?[^|;&\n]*?(?:[^'\"\s|;&]*/)?{_DRAFT_PATH_INSIDE}",
)

# Shape 4: awk -i inplace against a draft path
_AWK_INPLACE_DRAFT_RE = re.compile(
    rf"\bawk\b[^|;&\n]*?-i\s+inplace[^|;&\n]*?(?:[^'\"\s|;&]*/)?{_DRAFT_PATH_INSIDE}",
)

# Shape 5: perl -i (in-place) against a draft path
_PERL_INPLACE_DRAFT_RE = re.compile(
    rf"\bperl\b[^|;&\n]*?-i(?:\.[A-Za-z0-9]+)?[^|;&\n]*?(?:[^'\"\s|;&]*/)?{_DRAFT_PATH_INSIDE}",
)

# Shape 6: cp / mv with a draft path as destination (last positional arg).
# Conservative: only fires when the LAST whitespace-delimited token matches
# a draft path. cp/mv SRC DEST means DEST is the draft (overwrite).
_CP_MV_DRAFT_DEST_RE = re.compile(
    rf"\b(?:cp|mv|rsync|install)\b[^|;&\n]*\s(?:[^'\"\s|;&]*/)?{_DRAFT_PATH_INSIDE}\s*(?:$|[|;&])",
)

# Shape 7: Inline Python / Node / Ruby writes to a draft path.
# `python -c "open('path', 'w')"`, `python3 -c "Path('path').write_text(...)"`,
# `node -e "fs.writeFileSync('path', ...)"`, etc.
_INLINE_PYTHON_DRAFT_WRITE_RE = re.compile(
    rf"(?:python|python3|node|nodejs|ruby|deno|bun)\b[^|;&\n]*?(?:open|writeFileSync|write_text|write\(|writeFile|File\.write|IO\.write|fs\.writeFile)[^|;&\n]*?{_DRAFT_PATH_INSIDE}",
    re.DOTALL,
)

# Shape 8: ed / ex / vim ex-command in-place edits against a draft path.
# `ed path << 'EOF' ... EOF`, `vim -es path -c "..."`, `ex -sc "..." path`.
_EX_VIM_DRAFT_RE = re.compile(
    rf"\b(?:ed|ex|vim|nvim|vi)\b[^|;&\n]*?(?:-[escSI]+|<<\s*['\"]?[A-Z]+)[^|;&\n]*?(?:[^'\"\s|;&]*/)?{_DRAFT_PATH_INSIDE}",
)


# Shape 9: NotebookEdit cell-body inline code writes a draft path. The cell
# body is plain Python / shell magic (no leading interpreter token), so we
# detect any open/write_text/writeFileSync/Path-write/io-write expression
# whose argument is a draft path.
# r36-rebuttal: lane-GAP-FIX-3-C tools/agent-pathspec-register.py declared 5 files at lane start
_NAKED_PYTHON_DRAFT_WRITE_RE = re.compile(
    rf"(?:open|writeFileSync|write_text|writeFile|File\.write|IO\.write|fs\.writeFile|Path)\s*\([^)]*['\"][^'\"]*?{_DRAFT_PATH_INSIDE}[^'\"]*['\"]",
    re.DOTALL,
)


def _matches_bash_draft_write(command: str) -> tuple[bool, str]:
    """Return (matched, shape_name) when the Bash command body (or
    NotebookEdit cell source) writes to a draft path via any of
    shell-redirect / tee / sed -i / awk -i inplace / perl -i / cp / mv /
    inline-python / inline-node / ed / vim ex / naked-python-open.

    Conservative: requires the draft-path pattern AND a recognized write
    operator. Plain `cat file.md` or `grep submissions/...` do NOT match.
    """
    if not _DRAFT_PATH_RE.search(command):
        return (False, "")
    if _SHELL_REDIRECT_TO_DRAFT_RE.search(command):
        return (True, "redirect")
    if _TEE_TO_DRAFT_RE.search(command):
        return (True, "tee")
    if _SED_INPLACE_DRAFT_RE.search(command):
        return (True, "sed-inplace")
    if _AWK_INPLACE_DRAFT_RE.search(command):
        return (True, "awk-inplace")
    if _PERL_INPLACE_DRAFT_RE.search(command):
        return (True, "perl-inplace")
    if _CP_MV_DRAFT_DEST_RE.search(command):
        return (True, "cp-mv-dest")
    if _INLINE_PYTHON_DRAFT_WRITE_RE.search(command):
        return (True, "inline-interp")
    if _EX_VIM_DRAFT_RE.search(command):
        return (True, "ed-vim")
    if _NAKED_PYTHON_DRAFT_WRITE_RE.search(command):
        return (True, "naked-python-open")
    return (False, "")


def _extract_extreme_rebuttal(command: str, gap_id: str) -> str:
    """Scan the command body for an embedded
    `# extreme-rebuttal-<gap_id>: <reason>` shell-comment marker. Returns
    the reason string if present and non-empty (<=200 chars), else "".

    The marker MUST appear in the same command body (multi-line allowed).
    Operators chain the marker as a leading shell comment:

        # extreme-rebuttal-gap1-no-verify: operator-driven test of CI bypass
        git commit --no-verify -m "test"
    """
    pat = re.compile(
        rf"#\s*extreme-rebuttal-{re.escape(gap_id)}\s*:\s*(.{{1,200}}?)(?:$|\n)",
        re.MULTILINE,
    )
    m = pat.search(command)
    if not m:
        return ""
    reason = m.group(1).strip()
    if not reason:
        return ""
    return reason

# Severity-decision triggers in Agent prompts.
_SEVERITY_DECISION_RE = re.compile(
    r"\b(severity|tier|critical|high|medium|low)\s+"
    r"(?:decision|escalation|downgrade|walk[-\s]?back|file|claim|amend|asymmetr|upgrade)\b",
    re.IGNORECASE,
)
_DRILL_LANE_RE = re.compile(r"\bdrill\b|hunt[-_]?(class|lane)|DRILL-\d+", re.IGNORECASE)

# Audit-workspace signal (same vocabulary as auditooor-mcp-first-enforce.sh)
_AUDIT_WORKSPACE_RE = re.compile(
    r"/audits/|auditooor|\b(nuva|spark|dydx|centrifuge|morpho|mezo|polymarket|hyperbridge|near)\b",
    re.IGNORECASE,
)


def _classify_filepath(path: str) -> tuple[str, list[str]]:
    """Return (filepath_class, additional_rule_citations).

    The filepath_class is one of:
      - draft-file           : submissions/<status>/<slug>/<slug>.<ext>
      - tracker-file         : submissions/SUBMISSIONS.md (etc.)
      - workspace-ledger     : <ws>/.auditooor/...
      - lesson-anchor        : submissions/_lessons-learned/...
      - tools-py             : tools/*.py inside auditooor-mcp tree
      - tools-non-py         : tools/* but not *.py
      - docs                 : docs/*
      - reports              : reports/*
      - workspace-local      : anything else under audit / auditooor tree
      - cwd-out-of-tree      : path outside known audit/auditooor trees

    Citations are pre-populated for classes whose mere mention requires
    a rule citation regardless of the surrounding Bash/Edit/Write verb
    (e.g. any write to a draft file triggers L34).
    """
    citations: list[str] = []
    if not path:
        return ("cwd-out-of-tree", citations)

    normalised = path.replace("\\", "/")
    parts = [p for p in normalised.split("/") if p]

    # workspace-ledger -> any .auditooor/ subtree under a workspace
    if ".auditooor" in parts:
        return ("workspace-ledger", citations)

    if "submissions" in parts:
        # Find the index of "submissions" and inspect what follows.
        idx = parts.index("submissions")
        tail = parts[idx + 1:]
        # lesson-anchor: submissions/_lessons-learned/...
        if tail and tail[0] in {"_lessons-learned", "_lessons_learned"}:
            return ("lesson-anchor", citations)
        # tracker-file: submissions/<TRACKER_STEM>.md or submissions/<status>/<TRACKER_STEM>.md
        if tail and len(tail) <= 2:
            last = tail[-1]
            stem = re.sub(r"\.(md|json|jsonl|yaml|yml|csv|tsv|hash)(\.bak.*)?$", "", last, flags=re.IGNORECASE)
            if stem.upper() in _TRACKER_STEMS:
                return ("tracker-file", citations)
        # draft-file: submissions/<status>/<slug>/<slug>.<ext>
        if tail and tail[0] in _DRAFT_STATUS_DIRS and len(tail) >= 2:
            citations.append("L34")
            return ("draft-file", citations)
        # legacy flat draft at submissions/ root not matching tracker
        if tail and len(tail) == 1 and tail[0].lower().endswith(".md"):
            citations.append("L34")
            return ("draft-file", citations)

    # tools/*.py inside auditooor-mcp repo
    if "tools" in parts:
        idx = parts.index("tools")
        tail = parts[idx + 1:]
        if tail:
            if tail[-1].endswith(".py"):
                citations.append("R36")
                return ("tools-py", citations)
            return ("tools-non-py", citations)

    if "docs" in parts:
        return ("docs", [])
    if "reports" in parts:
        return ("reports", [])

    if _AUDIT_WORKSPACE_RE.search(normalised):
        return ("workspace-local", citations)
    return ("cwd-out-of-tree", citations)


# ---------------------------------------------------------------------------
# Classification record
# ---------------------------------------------------------------------------

@dataclass
class Classification:
    action_signature: str = "<allow-by-default>"
    tool_name: str = ""
    filepath_class: str = ""
    required_rule_citations: list[str] = field(default_factory=list)
    exception_marker_required: bool = False
    context_signals: dict[str, Any] = field(default_factory=dict)
    techupgrades: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "action_signature": self.action_signature,
            "tool_name": self.tool_name,
            "filepath_class": self.filepath_class,
            "required_rule_citations": self.required_rule_citations,
            "exception_marker_required": self.exception_marker_required,
            "context_signals": self.context_signals,
            "techupgrades": self.techupgrades,
            "remediation": self.remediation,
        }


# ---------------------------------------------------------------------------
# Per-tool classifiers
# ---------------------------------------------------------------------------

# r36-rebuttal: declared in agent_pathspec.json for lane ENFORCEMENT-PHASE-1-TIER-A; tools/agent-pathspec-register.py invoked at lane start
def _classify_bash(tool_input: dict[str, Any]) -> Classification:
    command = str(tool_input.get("command", "") or "")
    cls = Classification(tool_name="Bash")

    # Audit-workspace context probe: only if a cwd / command body mentions
    # an audit workspace do we apply auditooor-discipline gates. This keeps
    # the hook silent for unrelated dev work in other projects.
    audit_workspace_signal = bool(_AUDIT_WORKSPACE_RE.search(command))
    cls.context_signals["audit_workspace_signal"] = audit_workspace_signal

    # -----------------------------------------------------------------
    # Phase 1 Tier-A EXTREME gaps (6 operator-incident-anchored patterns;
    # checked BEFORE the generic destructive-op classifier so each gap
    # gets a specific DENY message).
    # tools/agent-pathspec-register.py is the R36 registration point.
    # -----------------------------------------------------------------

    # Gap 1: --no-verify on any git operation. NEVER-SKIP-HOOKS.
    if _NO_VERIFY_RE.search(command):
        cls.action_signature = "Bash<git-no-verify>"
        cls.required_rule_citations = ["NEVER-SKIP-HOOKS"]
        cls.exception_marker_required = True
        cls.context_signals["extreme_gap"] = "gap1-no-verify"
        cls.context_signals["extreme_rebuttal_id"] = "gap1-no-verify"
        cls.context_signals["override_env"] = "AUDITOOOR_NEVER_SKIP_HOOKS_BYPASS"
        cls.remediation = (
            "EXTREME-GAP-1 NEVER-SKIP-HOOKS: --no-verify forbidden. "
            "Skipping hooks defeats every other rule in the enforcement "
            "stack. CLAUDE.md hard rule: 'Never skip hooks (--no-verify) "
            "or bypass signing unless the user has explicitly asked for "
            "it. If a hook fails, investigate and fix the underlying "
            "issue.' Override: set AUDITOOOR_NEVER_SKIP_HOOKS_BYPASS=1 "
            "OR embed '# extreme-rebuttal-gap1-no-verify: <reason>' as "
            "a leading shell comment (<=200 chars)."
        )
        return cls

    # Gap 2: git push -f / --force to main/master/HEAD. NEVER-FORCE-PUSH-MAIN.
    if _FORCE_PUSH_MAIN_RE.search(command):
        cls.action_signature = "Bash<git-force-push-main>"
        cls.required_rule_citations = ["NEVER-FORCE-PUSH-MAIN"]
        cls.exception_marker_required = True
        cls.context_signals["extreme_gap"] = "gap2-force-push-main"
        cls.context_signals["extreme_rebuttal_id"] = "gap2-force-push-main"
        cls.context_signals["override_env"] = "AUDITOOOR_NEVER_FORCE_PUSH_BYPASS"
        cls.remediation = (
            "EXTREME-GAP-2 NEVER-FORCE-PUSH-MAIN: git push -f / --force to "
            "main / master / HEAD forbidden. Destroys reflog + MCP token "
            "state on origin/main. CLAUDE.md hard rule: 'Never force push "
            "to main/master, warn the user if they request it.' "
            "Override: set AUDITOOOR_NEVER_FORCE_PUSH_BYPASS=1 OR embed "
            "'# extreme-rebuttal-gap2-force-push-main: <reason>' (<=200 chars)."
        )
        return cls

    # Gap 3: git config WRITE operation. NEVER-GIT-CONFIG-CHANGE.
    # r36-rebuttal: declared in agent_pathspec.json; tools/agent-pathspec-register.py invoked
    if _is_git_config_write(command):
        cls.action_signature = "Bash<git-config-write>"
        cls.required_rule_citations = ["NEVER-GIT-CONFIG-CHANGE"]
        cls.exception_marker_required = True
        cls.context_signals["extreme_gap"] = "gap3-git-config-write"
        cls.context_signals["extreme_rebuttal_id"] = "gap3-git-config-write"
        cls.context_signals["override_env"] = "AUDITOOOR_NEVER_GIT_CONFIG_BYPASS"
        cls.remediation = (
            "EXTREME-GAP-3 NEVER-GIT-CONFIG-CHANGE: git config write "
            "operation detected (--global / --system / --local / --add / "
            "--unset / KEY=VALUE). CLAUDE.md hard rule: 'NEVER update the "
            "git config'. Read operations (--get, --list, --get-all, "
            "--show-*) are allowed. Override: set "
            "AUDITOOOR_NEVER_GIT_CONFIG_BYPASS=1 OR embed "
            "'# extreme-rebuttal-gap3-git-config-write: <reason>' (<=200 chars)."
        )
        return cls

    # Gap 4: gh gist delete. NEVER-DELETE-GISTS.
    if _GIST_DELETE_RE.search(command):
        cls.action_signature = "Bash<gh-gist-delete>"
        cls.required_rule_citations = ["NEVER-DELETE-GISTS"]
        cls.exception_marker_required = True
        cls.context_signals["extreme_gap"] = "gap4-gist-delete"
        cls.context_signals["extreme_rebuttal_id"] = "gap4-gist-delete"
        cls.context_signals["override_env"] = "AUDITOOOR_NEVER_DELETE_GISTS_BYPASS"
        cls.remediation = (
            "EXTREME-GAP-4 NEVER-DELETE-GISTS: gh gist delete forbidden. "
            "URL preservation matters (per memory anchor "
            "feedback_never_delete_gists.md). Wipe revisions via git "
            "clone + orphan-branch force-push to preserve the URL. "
            "Override: set AUDITOOOR_NEVER_DELETE_GISTS_BYPASS=1 OR embed "
            "'# extreme-rebuttal-gap4-gist-delete: <reason>' (<=200 chars)."
        )
        return cls

    # Gap 5: incrementNonce on polymarket wallet.
    if _INCREMENT_NONCE_RE.search(command):
        cls.action_signature = "Bash<incrementNonce>"
        cls.required_rule_citations = ["NEVER-INCREMENTNONCE"]
        cls.exception_marker_required = True
        cls.context_signals["extreme_gap"] = "gap5-incrementNonce"
        cls.context_signals["extreme_rebuttal_id"] = "gap5-incrementNonce"
        cls.context_signals["override_env"] = "AUDITOOOR_NEVER_INCREMENTNONCE_BYPASS"
        cls.remediation = (
            "EXTREME-GAP-5 NEVER-INCREMENTNONCE: incrementNonce call "
            "detected. Polymarket CLAUDE.md hard rule: 'NEVER call "
            "incrementNonce() - gets wallet banned'. wallet1 + wallet2 "
            "ALREADY BANNED for testing this; this single call bans "
            "wallet3 too. Override: set "
            "AUDITOOOR_NEVER_INCREMENTNONCE_BYPASS=1 OR embed "
            "'# extreme-rebuttal-gap5-incrementNonce: <reason>' (<=200 chars)."
        )
        return cls

    # r36-rebuttal: lane LIFT-22-R55-REGEX-TIGHTEN declared in agent_pathspec.json via tools/agent-pathspec-register.py
    # Gap 6: git reset --hard NOT via the wrapper script. R55-FOREGROUND.
    # LIFT-22: uses _is_destructive_git_op which strips inert contexts
    # (comments / echo'd docs / heredoc bodies / docstrings / test data
    # lists) BEFORE the regex match, removing the 4 FP classes from
    # LIFT-20, and also picks up subprocess.run(["git","reset","--hard"])
    # list-form (FN-1 fix).
    is_destruct, destruct_source = _is_destructive_git_op(command)
    if is_destruct and destruct_source in ("raw-reset-hard", "subprocess-list", "string-shell"):
        # Treat subprocess-list / string-shell wrappers around `git reset`
        # variants as Gap-6 EXTREME too; they bypass the wrapper script
        # exactly like the raw form. Only fire EXTREME when the verb is
        # reset (clean/stash/branch fall through to the generic path).
        if destruct_source == "raw-reset-hard" or (
            destruct_source in ("subprocess-list", "string-shell")
            and re.search(r"['\"]reset['\"]|reset\s+--(?:hard|merge|keep)", command)
        ):
            cls.action_signature = "Bash<git-reset-hard-raw>"
            cls.required_rule_citations = ["R55-FOREGROUND"]
            cls.exception_marker_required = True
            cls.context_signals["extreme_gap"] = "gap6-git-reset-hard-raw"
            cls.context_signals["extreme_rebuttal_id"] = "gap6-git-reset-hard-raw"
            cls.context_signals["override_env"] = "AUDITOOOR_R55_RAW_RESET_BYPASS"
            cls.context_signals["destruct_source"] = destruct_source
            cls.remediation = (
                "EXTREME-GAP-6 R55-FOREGROUND: raw 'git reset --hard' detected "
                "NOT routed through tools/git-hooks/git-reset-safe.sh. R55 "
                "anchor: iter17 OOOOO lane (2026-05-23) ran two consecutive "
                "raw resets that wiped Lane YYYY's iter15 brief-anchor edits "
                "to 7 bug-class briefs. Use the wrapper which gates on "
                "sibling-uncommitted-edit check OR set R55_REBUTTAL='<reason>' "
                "OR set AUDITOOOR_R55_RAW_RESET_BYPASS=1 OR embed "
                "'# extreme-rebuttal-gap6-git-reset-hard-raw: <reason>' "
                "(<=200 chars)."
            )
            return cls

    # r36-rebuttal: lane-GAP-FIX-3-C tools/agent-pathspec-register.py declared 5 files at lane start
    # -----------------------------------------------------------------
    # Gap #56: Bash shell-write draft bypass (closes ENFORCEMENT-AUDIT
    # gap; raises L34 citation requirement on Bash command bodies that
    # write to draft files via shell redirects / sed -i / awk -i inplace
    # / perl -i / cp / mv / inline-python / inline-node / ed / vim ex.
    # Runs AFTER the EXTREME gaps so they keep first-class diagnostics.
    # -----------------------------------------------------------------
    matched, shape = _matches_bash_draft_write(command)
    if matched:
        cls.action_signature = "Bash<draft-file-write-via-shell>"
        cls.filepath_class = "draft-file"
        cls.required_rule_citations = ["L34"]
        cls.exception_marker_required = True
        cls.context_signals["shell_draft_write_shape"] = shape
        cls.remediation = (
            "Gap #56 - Bash shell-write to a draft file detected "
            f"(shape={shape}). L34: any write to "
            "submissions/<status>/<slug>/<slug>.<ext> requires explicit "
            "operator authorization NAMING this draft. A blanket "
            "'fix R-rule violations' directive is NOT enough. "
            "Override: append <!-- l34-rebuttal: <reason> --> to the "
            "draft body or the command body, OR set "
            "AUDITOOOR_L34_OPERATOR_AUTH='<reason>' env."
        )
        return cls

    # -----------------------------------------------------------------
    # Original classifiers (preserved; run after the EXTREME-gap checks).
    # -----------------------------------------------------------------

    # r36-rebuttal: lane LIFT-22-R55-REGEX-TIGHTEN declared in agent_pathspec.json via tools/agent-pathspec-register.py
    # Destructive git ops -> R55 (sibling-uncommitted-edit check).
    # LIFT-22: re-uses the EXTREME-Gap-6 destructive classifier result
    # (computed above and stored in `is_destruct` / `destruct_source`)
    # so the FP carve-outs (bash comments / echo / heredoc / docstrings
    # / grep / test-data lists) and the FN coverage (subprocess list
    # form, os.system / sh -c string form) are inherited here too. The
    # EXTREME path already returned for the reset-only verb; this path
    # catches the clean/stash/branch/push verbs plus the subprocess-list
    # versions of those that aren't gated by the wrapper.
    if is_destruct and destruct_source in ("generic-destructive", "subprocess-list", "string-shell"):
        cls.action_signature = "Bash<git-destructive-op>"
        cls.required_rule_citations = ["R55"]
        cls.exception_marker_required = True
        cls.context_signals["destruct_source"] = destruct_source
        cls.remediation = (
            "Destructive git op detected. Per R55, wrap with "
            "tools/git-hooks/git-reset-safe.sh or run "
            "tools/git-hooks/pre-destructive-op-sibling-check.sh first. "
            "Override: export R55_REBUTTAL='<reason>' (<=200 chars)."
        )
        return cls

    # git commit -> requires context_pack_id in commit body / env.
    if _GIT_COMMIT_RE.search(command):
        cls.action_signature = "Bash<git-commit>"
        cls.required_rule_citations = ["context-pack-id"]
        cls.exception_marker_required = True
        cls.context_signals["wants_context_pack_id"] = True
        cls.remediation = (
            "git commit requires context_pack_id + context_pack_hash in "
            "the commit message body (per CLAUDE.md MCP-first rule). The "
            "commit-msg hook already enforces this; the universal hook "
            "logs the same expectation pre-flight."
        )
        return cls

    # git push -> requires MCP session token.
    if _GIT_PUSH_RE.search(command):
        cls.action_signature = "Bash<git-push>"
        cls.required_rule_citations = ["mcp-session-token"]
        cls.exception_marker_required = True
        cls.context_signals["wants_mcp_session_token"] = True
        cls.remediation = (
            "git push requires AUDITOOOR_MCP_SESSION_TOKEN. Run Layer-1 "
            "MCP recall (bash /Users/wolf/.auditooor/bin/auditooor-session-"
            "start.sh <ws>) to issue a token."
        )
        return cls

    # make audit / audit-deep / audit-fast / hunt -> recommend phase ordering.
    if _MAKE_AUDIT_RE.search(command):
        cls.action_signature = "Bash<make-audit-or-hunt>"
        cls.required_rule_citations = []  # advisory-only today
        cls.techupgrades.append(
            "make-audit-or-hunt phase-ordering enforcement is a "
            "techupgrade: requires CAPABILITY-GAP-29 (phase-ordering "
            "check) tooling before we can fail-closed."
        )
        cls.remediation = (
            "make audit/hunt detected. Phase-ordering enforcement is a "
            "future capability; currently advisory-only."
        )
        return cls

    cls.action_signature = "Bash<other>"
    return cls


# r36-rebuttal: lane-GAP-FIX-3-C tools/agent-pathspec-register.py declared 5 files at lane start
def _classify_edit_or_write(tool_name: str, tool_input: dict[str, Any]) -> Classification:
    # NotebookEdit uses `notebook_path` rather than `file_path` to identify
    # the target notebook. Some NotebookEdit payloads also include
    # `cell.source` whose body may contain draft-write patterns; we route
    # those through the Bash shell-write classifier to honour Gap #56.
    path = str(
        tool_input.get("file_path", "")
        or tool_input.get("notebook_path", "")
        or ""
    )
    cls = Classification(tool_name=tool_name)

    filepath_class, extra_citations = _classify_filepath(path)
    cls.filepath_class = filepath_class

    # NotebookEdit-specific: a cell source body may itself write to a draft
    # file via inline Python / shell magic / bang-prefixed commands. Treat
    # the cell source as a Bash-equivalent context for Gap #56 detection.
    if tool_name == "NotebookEdit":
        cell_source = ""
        cell = tool_input.get("cell")
        if isinstance(cell, dict):
            src = cell.get("source")
            if isinstance(src, str):
                cell_source = src
            elif isinstance(src, list):
                cell_source = "\n".join(str(s) for s in src)
        # Some Anthropic harnesses pass `new_source` / `cell_source` directly.
        if not cell_source:
            for fallback_key in ("new_source", "cell_source", "source", "content", "new_string"):
                v = tool_input.get(fallback_key)
                if isinstance(v, str):
                    cell_source = v
                    break
        if cell_source:
            matched, shape = _matches_bash_draft_write(cell_source)
            if matched:
                cls.action_signature = "NotebookEdit<draft-file-write-via-cell>"
                cls.filepath_class = "draft-file"
                cls.required_rule_citations = ["L34"]
                cls.exception_marker_required = True
                cls.context_signals["cell_draft_write_shape"] = shape
                cls.remediation = (
                    "Gap #57 - NotebookEdit cell body writes to a draft "
                    f"file (shape={shape}). L34: any write to "
                    "submissions/<status>/<slug>/<slug>.<ext> requires "
                    "explicit operator authorization NAMING this draft. "
                    "Override: append <!-- l34-rebuttal: <reason> --> to "
                    "the draft or cell source, OR set "
                    "AUDITOOOR_L34_OPERATOR_AUTH='<reason>' env."
                )
                return cls

    if filepath_class == "draft-file":
        cls.action_signature = f"{tool_name}<submissions-draft-file>"
        cls.required_rule_citations = ["L34"]
        cls.exception_marker_required = True
        cls.remediation = (
            "L34: any edit/write to submissions/<status>/<slug>/<slug>.<ext> "
            "requires explicit operator authorization NAMING this draft. "
            "A blanket 'fix R-rule violations' directive is not enough. "
            "Override: append <!-- l34-rebuttal: <reason> --> to the draft "
            "OR set AUDITOOOR_L34_OPERATOR_AUTH='<reason>' env."
        )
        return cls

    if filepath_class == "tools-py":
        cls.action_signature = f"{tool_name}<tools-py>"
        cls.required_rule_citations = ["R36"]
        cls.exception_marker_required = True
        cls.remediation = (
            "R36 parallel-worktree pathspec discipline: any write to "
            "tools/*.py must be declared in .auditooor/agent_pathspec.json "
            "via tools/agent-pathspec-register.py. Override: <!-- r36-"
            "rebuttal: <reason> -->."
        )
        return cls

    if filepath_class == "tracker-file":
        cls.action_signature = f"{tool_name}<tracker-file>"
        cls.required_rule_citations = []
        cls.remediation = (
            "tracker-file edit detected (auto-executable per L34 v2 "
            "5-bucket classification; SUBMISSIONS.md is operator-facing "
            "metadata, not draft content)."
        )
        return cls

    if filepath_class == "workspace-ledger":
        cls.action_signature = f"{tool_name}<workspace-ledger>"
        cls.required_rule_citations = []
        return cls

    if filepath_class == "lesson-anchor":
        cls.action_signature = f"{tool_name}<lesson-anchor>"
        cls.required_rule_citations = []
        return cls

    cls.action_signature = f"{tool_name}<{filepath_class}>"
    if extra_citations:
        cls.required_rule_citations = extra_citations
        cls.exception_marker_required = bool(extra_citations)
    return cls


# r36-rebuttal: lane-RULE-64-CLAIM-VERIFICATION declared in agent_pathspec.json via tools/agent-pathspec-register.py at lane start
# Rule R64 (codified 2026-05-26): orchestrator Agent prompts that reference
# tool paths, MCP callables, Check #N, R-rule IDs, schemas, or make
# targets that DO NOT exist in the canonical inventory are HALLUCINATIONS.
# L25/L26 only catch this AFTER the worker reads source files; R64 catches
# it BEFORE the worker is dispatched. We run a lightweight extraction here
# in the classifier and emit a `prompt-claim-verification` citation
# requirement when ANY claim shape is detected. The hook then defers to
# tools/r64-prompt-claim-verifier.py (or canonical-inventory.py --check)
# for the actual lookup.

_R64_CLAIM_SHAPES_RE = re.compile(
    # tools/foo.py | tools/foo.sh
    r"(?:\./)?tools/[A-Za-z0-9_./-]+\.(?:py|sh)\b"
    # vault_<something>
    r"|\bvault_[a-z][a-z0-9_]+\b"
    # Check #N
    r"|\bCheck\s*#\s*\d+\b"
    # R52, L34, Rule 52
    r"|\b(?:Rule\s+)?[RL][\s_-]?\d+[A-Z]?\b"
    # auditooor.foo.v1
    r"|\bauditooor\.[a-z0-9_]+\.v\d+\b"
    # make foo-bar
    r"|\bmake\s+[a-zA-Z][a-zA-Z0-9_-]*\b"
    # Numeric counts with corpus-noun (10K Cantina, 5000 findings)
    r"|\b\d{1,3}(?:[,.]\d{3})+\s+(?:cantina|solodit|immunefi|finding|rationale|record|verdict)s?\b"
    r"|\b\d+[Kk]\s+(?:cantina|solodit|immunefi|finding|rationale|record|verdict)s?\b"
    r"|\b\d{3,}\s+(?:cantina|solodit|immunefi|finding|rationale|record|verdict)s?\b",
    re.IGNORECASE,
)


def _classify_agent(tool_input: dict[str, Any]) -> Classification:
    prompt = str(tool_input.get("prompt", "") or "")
    cls = Classification(tool_name="Agent")
    cls.context_signals["audit_workspace_signal"] = bool(
        _AUDIT_WORKSPACE_RE.search(prompt)
    )

    # R64: scan for factual claim shapes. When any are present, the prompt
    # must either (a) cite tools/r64-prompt-claim-verifier.py / tools/canonical-
    # inventory.py with the verification output inlined, or (b) carry an
    # r64-rebuttal marker. The enforce hook does the rebuttal-marker check.
    claim_matches = _R64_CLAIM_SHAPES_RE.findall(prompt)
    if claim_matches:
        cls.context_signals["r64_claim_shape_count"] = len(claim_matches)
        cls.context_signals["r64_claim_shapes_sample"] = list(
            dict.fromkeys(claim_matches)
        )[:10]

    if _SEVERITY_DECISION_RE.search(prompt):
        cls.action_signature = "Agent<severity-decision-context>"
        citations = ["R14"]
        # R64 piggy-backs when claim shapes are present.
        if claim_matches:
            citations.append("R64")
        cls.required_rule_citations = citations
        cls.exception_marker_required = True
        cls.remediation = (
            "Agent dispatch contains severity-decision context. Per Rule "
            "14 (upside-asymmetric filing), invoke "
            "tools/triager-amend-asymmetry.py --workspace <ws> --candidate-"
            "severity <T+1> first; cite its verdict in the brief, OR add "
            "<!-- r14-rebuttal: explicit-not-applicable --> to the prompt."
        )
        return cls

    if _DRILL_LANE_RE.search(prompt):
        cls.action_signature = "Agent<drill-class-lane>"
        citations = ["hacker-mcp-suite"]
        if claim_matches:
            citations.append("R64")
        cls.required_rule_citations = citations
        cls.exception_marker_required = True
        cls.remediation = (
            "Drill-class Agent dispatch detected. Per HACKER_LANE_BRIEF_"
            "TEMPLATE.md, drill-class lanes must cite the hacker MCP "
            "suite queries (vault_hacker_brief_for_lane, vault_hackerman_"
            "novel_vector_context, vault_chained_attack_plan_context). "
            "Override: <!-- hacker-mcp-rebuttal: <reason> -->."
        )
        return cls

    # R64-only path: claim shapes present but no severity / drill signal.
    if claim_matches and cls.context_signals["audit_workspace_signal"]:
        cls.action_signature = "Agent<unverified-claim>"
        cls.required_rule_citations = ["R64"]
        cls.exception_marker_required = True
        cls.remediation = (
            "R64 prompt-claim verification: this Agent dispatch contains "
            f"{len(claim_matches)} factual-claim shape(s) "
            "(tool path / MCP callable / Check #N / R-rule / schema / "
            "record-count). Per Rule R64 (codified 2026-05-26 after the "
            "'10K Cantina rationales' hallucination), claims must be "
            "verified against the canonical inventory BEFORE dispatch. "
            "Run: python3 tools/r64-prompt-claim-verifier.py <prompt-file> "
            "OR python3 tools/canonical-inventory.py --check '<claim>'. "
            "Override: append <!-- r64-rebuttal: <reason up to 200 chars> "
            "--> to the prompt body."
        )
        return cls

    if cls.context_signals["audit_workspace_signal"]:
        cls.action_signature = "Agent<audit-workspace-dispatch>"
        # MCP-first enforcement is already covered by
        # auditooor-mcp-first-enforce.sh; we leave it to that hook so the
        # universal hook does not double-block.
        return cls

    cls.action_signature = "Agent<non-audit-dispatch>"
    return cls


# ---------------------------------------------------------------------------
# Top-level dispatcher
# ---------------------------------------------------------------------------

def classify(payload: dict[str, Any]) -> Classification:
    tool_name = str(payload.get("tool_name", "") or "")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}

    # r36-rebuttal: lane-GAP-FIX-3-C tools/agent-pathspec-register.py declared 5 files at lane start
    if tool_name == "Bash":
        return _classify_bash(tool_input)
    if tool_name in {"Edit", "Write", "MultiEdit", "NotebookEdit"}:
        # Gap #57: NotebookEdit was previously falling through to
        # <allow-by-default>. Route it through the same Edit/Write
        # classifier so it inherits L34/R36 classification on draft +
        # tools/ paths AND so its cell.source is scanned for the
        # Gap #56 shell-write shapes.
        return _classify_edit_or_write(tool_name, tool_input)
    if tool_name in {"Agent", "Task"}:
        return _classify_agent(tool_input)
    if tool_name == "Read":
        path = str(tool_input.get("file_path", "") or "")
        filepath_class, _ = _classify_filepath(path)
        cls = Classification(
            tool_name="Read",
            action_signature=f"Read<{filepath_class}>",
            filepath_class=filepath_class,
        )
        # Reads are read-only; never require rule citation.
        return cls

    return Classification(
        tool_name=tool_name,
        action_signature=f"{tool_name}<allow-by-default>",
    )


def main(argv: list[str]) -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        # Empty stdin -> fail-open allow with explicit signal.
        print(json.dumps(Classification(action_signature="<empty-payload>").to_payload()))
        return 0
    try:
        payload = json.loads(raw)
    except Exception as exc:
        # Fatal classifier bug surface: emit a fail-open payload and a
        # short error so the consuming hook can record + allow.
        out = Classification(
            action_signature="<parse-error>",
            techupgrades=[f"parse-error: {exc!r}"],
        ).to_payload()
        print(json.dumps(out))
        return 0
    cls = classify(payload)
    print(json.dumps(cls.to_payload()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
