#!/usr/bin/env bash
# ============================================================================
# Rule 36 - parallel-worktree-commit-pathspec-discipline hard gate.
# Gap #41 - per-file cross-lane pollution detection.
# Gap #55 - undeclared-file (orphan) staging discipline.
# Gap #50 - stale-pathspec-intent auto-prune at hook entry.
#
# Refuses a `git commit` whose staged file set absorbs work from a SIBLING
# lane's declared pathspec, even when the absorbed paths happen to appear in
# `.auditooor/agent_pathspec.json` under another live entry. This catches the
# sweep-add absorption failure mode that motivated FIX-C: the pre-FIX-C hook
# only validated that `.auditooor/agent_pathspec.json` was non-empty and that
# the staged union landed somewhere in any live agent's declared union, so a
# sweeping `git add -A` / `git add .` / `git add <dir>/` in Lane A absorbed
# Lane B's in-flight edits and silently passed the gate (see commits
# 36a4408329, a8569e977a, 9473cf3c22 attribution-correction commits, iter18
# phase MINUS-1).
#
# Gap #41 (codified 2026-05-26) extends the per-lane subset check with a
# per-file CROSS-CLAIM check: even when a staged file appears in the current
# lane's declared pathspec, the hook now refuses the commit if the SAME file
# also appears in any OTHER live (non-expired) lane's declared pathspec
# (cross-lane file pollution). Empirical anchors:
#
#   * SHA 1911dc4fe8 (CAPABILITY-GAP-8, 2026-05-25): the commit shipped its
#     declared 6 paths AND silently absorbed
#     reports/v3_iter_2026-05-25/lane_HYPERBRIDGE_AV9_FISHERMEN_VETO/results.md
#     - a SIBLING lane's results.md. The existing FIX-C check did not refuse
#     because the AV9 lane had not registered its intent (so the file was
#     classified as "undeclared OOS" rather than "sibling-absorbed") AND the
#     commit absorbed it under the GAP-8 lane's broader pathspec.
#   * SHA 2874c28a5b (DEPTH-TOOLS, 2026-05-26): the commit added a Check #109
#     stanza to tools/pre-submit-check.sh - a file that is system-shared
#     across multiple in-flight lanes. The check stanza got swept into the
#     DEPTH-TOOLS commit without explicit per-file confirmation that no
#     sibling lane was simultaneously editing the same file.
#
# Gap #41 + Gap #55 verdict vocabulary:
#   - pass-current-lane-only         (existing, subset check passes)
#   - pass-rebuttal-accepted         (existing, r36-rebuttal or gap41-rebuttal)
#   - fail-sibling-absorbed          (existing, FIX-C anchor)
#   - fail-undeclared-staged         (existing legacy-mode tag)
#   - fail-cross-lane-file-pollution (Gap #41: file in >=2 live lanes)
#   - fail-undeclared-file-staged    (Gap #55: file in NO live lane's pathspec)
#
# Gap #55 (codified 2026-05-26) formalises a long-standing failure mode that
# the Gap #41 sweep did not address: staged "orphan" files that are in NO
# live (non-expired) lane's declared pathspec. Such files were already
# refused by the hook in both CURRENT-LANE and LEGACY modes (they get
# absorbed into the `excess` bucket), but the verdict had no dedicated tag
# and no narrow override marker. Gap #55 adds:
#   * `fail-undeclared-file-staged` verdict line on the refusal output.
#   * `<!-- gap55-rebuttal: <reason up to 200 chars> -->` override that
#     silences ONLY the orphan-file refusal (it does NOT silence sibling
#     absorption or Gap #41 cross-claim - those still require r36-rebuttal).
# Empirical anchor: this session's 3 cross-pollination commits
# (56d2415118, 97dfd7f76d, 2874c28a5b) staged files that either belonged to
# nobody's live pathspec OR belonged only to stale-expired intents (which
# the hook drops at parse time, so they are effectively undeclared).
#
# Override markers (commit message), any of these forms accepted:
#   <!-- r36-rebuttal: <reason up to 200 chars> -->     (broadest umbrella)
#   <!-- gap41-rebuttal: <reason up to 200 chars> -->   (Gap #41 cross-claim only)
#   <!-- gap55-rebuttal: <reason up to 200 chars> -->   (Gap #55 undeclared only)
# The narrower markers silence ONLY their specific verdict; sibling-absorption
# (FIX-C) still requires r36-rebuttal.
#
# Behaviour:
#   * If `.auditooor/agent_pathspec.json` is absent, the hook is a no-op (pass).
#   * If the file exists but every declared agent entry has expired (its
#     `expires_at` is in the past), the hook is a no-op (pass).
#   * Otherwise the hook identifies the CURRENT lane via the
#     `R36_CURRENT_AGENT_ID` env var (falls back to `R55_CURRENT_AGENT_ID`
#     so callers do not need two env vars).
#       - If the env var matches a live agent: the staged set must be a
#         subset of the current lane's declared `files` UNION the always-
#         shared system-wide paths (phase_state.json, the lane's own
#         results.md, the pathspec file itself).
#       - If the env var is absent or does not match a live agent: legacy
#         behaviour applies (staged set must be in the UNION of every live
#         agent's pathspec). This preserves backward compatibility for
#         operator-driven commits that have no lane id but still respect
#         the union as a safety net.
#   * A `<!-- r36-rebuttal: <reason> -->` marker in the commit message (with a
#     non-empty reason, <=200 chars after whitespace collapse) allows an
#     intentional sweep commit and the hook passes.
#
# `.auditooor/agent_pathspec.json` schema (per-agent declared file list):
#   {
#     "agents": [
#       {
#         "agent_id": "wave3-agent-A",
#         "files": ["tools/foo.py", "tools/tests/test_foo.py", "docs/FOO.md"],
#         "expires_at": "2026-05-22T18:00:00Z"   # ISO-8601 UTC, 2h TTL
#       }
#     ]
#   }
# A flat top-level shape ({"files": [...], "expires_at": "..."}) is also
# accepted as a single-agent declaration. `files` entries are literal repo
# paths only; this hook does not glob-expand `*`, `?`, or `[` patterns.
#
# Always-shared system-wide paths (always treated as in-lane):
#   - .auditooor/agent_pathspec.json (every lane updates it on register)
#   - reports/v3_iter_*/phase_state.json (cross-lane coordination state)
#   - reports/v3_iter_*/<lane-dir>/results.md when <lane-dir> matches the
#     current agent_id (the lane's own report file)
# Env hook `R36_SYSTEM_WIDE_PATTERNS` (newline-separated regex list) can
# extend the system-wide allowlist.
#
# Installation (one of):
#   # (a) point git at this hooks directory; git looks for a file named
#   #     `pre-commit`, so symlink it:
#   ln -s pre-commit-pathspec-discipline.sh tools/git-hooks/pre-commit
#   git config core.hooksPath tools/git-hooks/
#
#   # (b) or copy it directly into the repo hooks dir:
#   cp tools/git-hooks/pre-commit-pathspec-discipline.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Override marker (commit message): <!-- r36-rebuttal: <reason up to 200 chars> -->
# ============================================================================

set -u

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ -z "${REPO_ROOT}" ]; then
  # Not in a git repo - nothing to enforce.
  exit 0
fi

PATHSPEC_FILE="${REPO_ROOT}/.auditooor/agent_pathspec.json"

# No declaration -> no-op pass.
if [ ! -f "${PATHSPEC_FILE}" ]; then
  exit 0
fi

# ---------------------------------------------------------------------------
# Gap #50 (codified 2026-05-26): auto-prune stale-expired entries on hook
# entry. SESSION-GAP-HUNT surfaced 6+ stale intents persisting across an
# operator session. Pruning at commit-hook entry keeps the pathspec lean and
# prevents stale entries from contaminating diagnostic output (the per-file
# ownership diagnostic emits one line per file; a pathspec polluted by
# 10+ stale entries would swamp legitimate signal).
#
# The prune is best-effort: a failure here MUST NOT block honest commits.
# Both the prune helper and the agent-pathspec-register.py tool fall back
# silently if not present. Set GAP50_DISABLE=1 to skip auto-prune.
# ---------------------------------------------------------------------------
GAP50_DISABLE="${GAP50_DISABLE:-}"
if [ "${GAP50_DISABLE}" != "1" ]; then
  REGISTER_TOOL="${REPO_ROOT}/tools/agent-pathspec-register.py"
  if [ -x "${REGISTER_TOOL}" ] || [ -f "${REGISTER_TOOL}" ]; then
    # Run silently; failures are non-fatal.
    python3 "${REGISTER_TOOL}" prune >/dev/null 2>&1 || true
  fi
fi

# Locate the commit message file. git passes it as $1 to commit-msg hooks but
# NOT to pre-commit hooks, so ask git for the worktree-aware COMMIT_EDITMSG
# path. Plain `REPO_ROOT/.git/COMMIT_EDITMSG` is wrong when `.git` is a
# worktree pointer file.
DEFAULT_COMMIT_MSG_FILE="$(git rev-parse --git-path COMMIT_EDITMSG 2>/dev/null || true)"
DEFAULT_COMMIT_MSG_FILE="${DEFAULT_COMMIT_MSG_FILE:-${REPO_ROOT}/.git/COMMIT_EDITMSG}"
COMMIT_MSG_FILE="${1:-${DEFAULT_COMMIT_MSG_FILE}}"
COMMIT_MSG=""
if [ -f "${COMMIT_MSG_FILE}" ]; then
  COMMIT_MSG="$(cat "${COMMIT_MSG_FILE}" 2>/dev/null)"
fi

# All decisioning is delegated to an embedded Python helper: it parses the JSON
# (no jq dependency), drops expired entries, identifies the current lane via
# env var, and compares the staged set against the current lane's declared
# pathspec (or the union as legacy fallback). It prints a verdict line and
# exits with the hook's intended exit code.
# Gap #97: route large staged file lists via tmpfile to avoid OS env-var size
# limit ("Argument list too long") when commits touch 10K+ files (operator-
# authorized megacommits / sweep commits). Python helper reads STAGED_FILES_FILE
# in preference to STAGED_FILES env var when set.
STAGED_FILES_FILE="$(mktemp -t r36_staged_files.XXXXXX)"
trap 'rm -f "${STAGED_FILES_FILE}"' EXIT
git diff --staged --name-only > "${STAGED_FILES_FILE}" 2>/dev/null

PATHSPEC_FILE="${PATHSPEC_FILE}" \
COMMIT_MSG="${COMMIT_MSG}" \
STAGED_FILES_FILE="${STAGED_FILES_FILE}" \
R36_CURRENT_AGENT_ID="${R36_CURRENT_AGENT_ID:-${R55_CURRENT_AGENT_ID:-}}" \
R36_SYSTEM_WIDE_PATTERNS="${R36_SYSTEM_WIDE_PATTERNS:-}" \
R36_STRICT_NO_LANE_ID="${R36_STRICT_NO_LANE_ID:-}" \
GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-}" \
GAP41_DISABLE="${GAP41_DISABLE:-}" \
GAP55_DISABLE="${GAP55_DISABLE:-}" \
R36_REBUTTAL="${R36_REBUTTAL:-}" \
python3 - <<'PYEOF'
import json
import os
import re
import sys
from datetime import datetime, timezone

pathspec_file = os.environ["PATHSPEC_FILE"]
commit_msg = os.environ.get("COMMIT_MSG", "")
# Gap #97: prefer tmpfile (avoids OS env-var size limit on 10K+ file commits).
_staged_files_file = os.environ.get("STAGED_FILES_FILE", "").strip()
if _staged_files_file and os.path.isfile(_staged_files_file):
    with open(_staged_files_file, "r", encoding="utf-8", errors="replace") as _f:
        staged_raw = _f.read()
else:
    staged_raw = os.environ.get("STAGED_FILES", "")
current_agent_id = os.environ.get("R36_CURRENT_AGENT_ID", "").strip()
strict_no_lane_id = os.environ.get("R36_STRICT_NO_LANE_ID", "").strip() == "1"
# Gap #41: GIT_AUTHOR_NAME is a soft fallback for current-lane attribution
# when neither R36_CURRENT_AGENT_ID nor R55_CURRENT_AGENT_ID is set. It is
# only consulted when the value matches a live agent_id exactly (no fuzzy
# match) - operator usernames typically do not match lane ids, so this is
# a no-op in the common case and only useful when a lane stores its lane id
# as its git author name.
git_author = os.environ.get("GIT_AUTHOR_NAME", "").strip()
# Gap #41: explicit kill-switch for the per-file cross-claim check. Default
# OFF (gate active). Set GAP41_DISABLE=1 to revert to pre-Gap-41 behaviour.
gap41_disable = os.environ.get("GAP41_DISABLE", "").strip() == "1"
# Gap #55: explicit kill-switch for the orphan-file refusal. Default OFF
# (gate active). Set GAP55_DISABLE=1 to silence the dedicated verdict and
# fall back to the legacy "REFUSED" message without the gap55 tag.
gap55_disable = os.environ.get("GAP55_DISABLE", "").strip() == "1"

staged = sorted({line.strip() for line in staged_raw.splitlines() if line.strip()})

# Nothing staged -> nothing to police.
if not staged:
    sys.exit(0)

try:
    with open(pathspec_file, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception as exc:
    # A malformed declaration must not silently disable the gate, but it also
    # must not hard-block honest work. Warn and pass.
    print(f"[r36-pathspec] WARNING: cannot parse {pathspec_file}: {exc}; gate skipped")
    sys.exit(0)


def _agents(payload):
    """Normalise to a list of agent entries."""
    if isinstance(payload, dict) and isinstance(payload.get("agents"), list):
        return [a for a in payload["agents"] if isinstance(a, dict)]
    # Flat single-agent shape.
    if isinstance(payload, dict) and "files" in payload:
        return [payload]
    return []


def _parse_ts(value):
    """Parse an ISO-8601 timestamp; return aware UTC datetime or None."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# Default system-wide path patterns - files that any lane may legitimately
# stage as part of normal lane bookkeeping. These bypass the staged-set
# subset check.
_DEFAULT_SYSTEM_PATTERNS = [
    # The pathspec file itself - every lane writes it on register.
    r"^\.auditooor/agent_pathspec\.json$",
    # The pathspec lock file (FIX-A fcntl sidecar).
    r"^\.auditooor/agent_pathspec\.json\.lock$",
    # Cross-lane phase coordination state.
    r"^reports/v3_iter_[^/]+/phase_state\.json$",
    # Older iter convention (hacker_brain_phase_state.json).
    r"^reports/v3_iter_[^/]+/hacker_brain_phase_state\.json$",
]


def _system_patterns_from_env():
    raw = os.environ.get("R36_SYSTEM_WIDE_PATTERNS", "")
    patterns = [p.strip() for p in raw.splitlines() if p.strip()]
    return patterns


def _is_system_wide(path, extra_patterns):
    for pat in _DEFAULT_SYSTEM_PATTERNS + extra_patterns:
        try:
            if re.match(pat, path):
                return True
        except re.error:
            continue
    return False


def _is_lane_own_results(path, agent_id):
    """A lane's own results.md / report files under its lane dir always pass.

    Convention: reports/v3_iter_*/lane_<id>/... or reports/v3_iter_*/<id>/...
    where <id> is derived from the agent_id by stripping a `lane-` prefix and
    normalising hyphens to underscores. This is forgiving: it accepts either
    the raw agent_id or the underscore-normalised form, and either prefixed
    (`lane_X`) or bare (`X`) directory naming.
    """
    if not agent_id:
        return False
    stem = agent_id
    if stem.startswith("lane-"):
        stem = stem[len("lane-"):]
    candidates = {
        stem,
        stem.replace("-", "_"),
        f"lane_{stem.replace('-', '_')}",
        f"lane-{stem}",
        agent_id,
    }
    for cand in candidates:
        prefix = f"reports/v3_iter_"
        # Match reports/v3_iter_*/<candidate>/...
        if re.match(rf"^{re.escape(prefix)}[^/]+/{re.escape(cand)}/", path):
            return True
    return False


now = datetime.now(timezone.utc)
agents = _agents(data)

live_union = set()
live_agents = []  # (agent_id, declared_set)
expired_agents = []
for agent in agents:
    files = agent.get("files")
    if not isinstance(files, list):
        continue
    declared = {str(f).strip() for f in files if str(f).strip()}
    if not declared:
        continue
    expires = _parse_ts(agent.get("expires_at"))
    agent_id = str(agent.get("agent_id", "<unnamed>"))
    if expires is not None and expires <= now:
        expired_agents.append(agent_id)
        continue
    # No expires_at, or in the future -> the declaration is live.
    live_union |= declared
    live_agents.append((agent_id, declared))

# No live declaration (file present but all entries expired / empty) -> no-op.
if not live_agents:
    sys.exit(0)

# Honour a non-empty <!-- r36-rebuttal: <reason> --> marker (<=200 chars after
# whitespace collapse). This silences the entire gate (sibling-absorption,
# excess-undeclared, AND Gap #41 cross-claim).
def _extract_rebuttal(msg, marker):
    m = re.search(rf"<!--\s*{re.escape(marker)}:\s*(.*?)\s*-->",
                  msg, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    reason = " ".join(m.group(1).split())
    if reason and len(reason) <= 200:
        return reason
    return None


r36_reason = _extract_rebuttal(commit_msg, "r36-rebuttal")
# Gap #97: pre-commit hook runs BEFORE COMMIT_EDITMSG is populated with -m
# message, so the in-file commit_msg may be stale (prior commit's message).
# Honor R36_REBUTTAL env var as a parallel-path rebuttal source for `git
# commit -m "..."` invocations. Same 200-char limit.
if not r36_reason:
    _env_r36 = " ".join(os.environ.get("R36_REBUTTAL", "").split())
    if _env_r36 and len(_env_r36) <= 200:
        r36_reason = _env_r36
if r36_reason:
    print(f"[r36-pathspec] rebuttal accepted: {r36_reason[:200]}")
    sys.exit(0)

# Gap #41: dedicated cross-lane file pollution rebuttal. Reserved for the
# narrower case where the operator confirms an intentional cross-lane file
# edit (e.g. integration commit touching tools/pre-submit-check.sh that
# multiple in-flight lanes also intend to touch). This marker silences
# ONLY the cross-claim check; it does NOT silence sibling-absorption or
# excess-undeclared, both of which still require r36-rebuttal.
gap41_reason = _extract_rebuttal(commit_msg, "gap41-rebuttal")
# Gap #55: dedicated orphan-file rebuttal. Reserved for the narrower case
# where the operator confirms an intentional commit of an undeclared
# (orphan) file - i.e. a file in NO live lane's pathspec. Typical use:
# operator-driven housekeeping or scratch-file cleanup that does not
# warrant registering a lane intent. This marker silences ONLY the
# orphan-file refusal; it does NOT silence sibling-absorption or Gap #41
# cross-claim, both of which still require r36-rebuttal.
gap55_reason = _extract_rebuttal(commit_msg, "gap55-rebuttal")

extra_patterns = _system_patterns_from_env()

# Gap #41: GIT_AUTHOR_NAME soft fallback. Only used when no R36/R55 env
# var was set AND the git author name matches a live agent_id exactly.
if not current_agent_id and git_author:
    live_ids = {aid for aid, _ in live_agents}
    if git_author in live_ids:
        current_agent_id = git_author
        print(f"[r36-pathspec] (Gap #41) GIT_AUTHOR_NAME='{git_author}' "
              f"matched a live lane; using it as current-lane id")

# Build the per-lane declared set, the sibling union, and the per-file
# ownership map. The ownership map is the data structure that powers the
# Gap #41 cross-claim check: each file -> sorted list of live agent_ids
# that declared it.
lane_declared = None
sibling_union = set()
file_ownership = {}  # path -> sorted list of live agent_ids that declared it
if current_agent_id:
    for aid, declared in live_agents:
        if aid == current_agent_id:
            lane_declared = declared
        else:
            sibling_union |= declared

# Always build the ownership map (needed by Gap #41 even in legacy mode).
for aid, declared in live_agents:
    for f in declared:
        file_ownership.setdefault(f, []).append(aid)
for f in file_ownership:
    file_ownership[f] = sorted(set(file_ownership[f]))


def _diagnose_ownership(staged_files):
    """Emit a one-line-per-file diagnostic of which live lane owns each
    staged file. Helps the operator see Gap #41 violations at a glance.
    """
    if not staged_files:
        return
    print(f"[r36-pathspec] (Gap #41) per-file ownership diagnostic:")
    print(f"  current lane : {current_agent_id or '<none>'}")
    print(f"  staged files : {len(staged_files)}")
    for f in staged_files:
        owners = file_ownership.get(f, [])
        if not owners:
            tag = "<unclaimed>"
        elif owners == [current_agent_id]:
            tag = f"owned-by: {current_agent_id} (current)"
        elif current_agent_id in owners and len(owners) > 1:
            others = [o for o in owners if o != current_agent_id]
            tag = f"CROSS-CLAIMED: current + {', '.join(others)}"
        elif current_agent_id not in owners:
            tag = f"sibling-owned: {', '.join(owners)}"
        else:
            tag = f"owned-by: {', '.join(owners)}"
        print(f"    - {f}  [{tag}]")

if lane_declared is not None:
    # CURRENT-LANE MODE: staged set must be subset of
    # current_lane.files ∪ system_wide ∪ lane-own-results-paths.
    excess = []
    sibling_absorbed = []
    cross_claimed = []  # Gap #41: files in current lane AND >=1 sibling lane
    for f in staged:
        # Gap #41: detect files that are in the current lane's pathspec AND
        # also appear in another live lane's pathspec. Even though they pass
        # the subset check, this is a cross-claim that risks sweeping the
        # sibling lane's in-flight work into this commit.
        owners = file_ownership.get(f, [])
        if not gap41_disable and current_agent_id in owners and len(owners) > 1:
            cross_claimed.append(f)
            # do NOT continue - still classify in the excess/sibling buckets
            # below, since cross-claim is orthogonal to subset membership.

        if f in lane_declared:
            continue
        if _is_system_wide(f, extra_patterns):
            continue
        if _is_lane_own_results(f, current_agent_id):
            continue
        # Out of lane's declared set. Classify:
        if f in sibling_union:
            sibling_absorbed.append(f)
        else:
            excess.append(f)

    # Gap #41: emit per-file diagnostic before any verdict decision.
    _diagnose_ownership(staged)

    # Gap #41: if cross-claim found but no other violation AND gap41-rebuttal
    # is present, accept (the operator confirmed the cross-claim is intentional).
    if cross_claimed and not excess and not sibling_absorbed:
        if gap41_reason:
            print(f"[r36-pathspec] (Gap #41) cross-claim rebuttal accepted: "
                  f"{gap41_reason[:200]}")
            print(f"[r36-pathspec] OK: {len(staged)} staged file(s) within "
                  f"current lane '{current_agent_id}' pathspec "
                  f"(cross-claim acknowledged)")
            sys.exit(0)
        # No rebuttal -> hard fail on cross-claim alone.
        print(f"[r36-pathspec] REFUSED (Gap #41): fail-cross-lane-file-pollution")
        print(f"  declaration : {pathspec_file}")
        print(f"  current lane: {current_agent_id}")
        print(f"  cross-claimed file(s) (in current lane AND >=1 sibling lane):")
        for f in cross_claimed:
            others = [o for o in file_ownership[f] if o != current_agent_id]
            print(f"    + {f}  [also claimed by: {', '.join(others)}]")
        print("")
        print("  Gap #41 - per-file cross-lane pollution detection.")
        print("  Even when a staged file is in the current lane's pathspec,")
        print("  if it ALSO appears in another live lane's intent, an")
        print("  uncoordinated commit can sweep that sibling's in-flight")
        print("  edits. Either:")
        print("    * coordinate with the sibling lane(s) and unregister")
        print("      one of the conflicting intents via")
        print("      `python3 tools/agent-pathspec-register.py unregister --lane <id>`")
        print("    * or, if the cross-claim is operator-intentional, add a")
        print("      non-empty marker:")
        print("      <!-- gap41-rebuttal: <reason up to 200 chars> -->")
        sys.exit(1)

    if not excess and not sibling_absorbed:
        print(f"[r36-pathspec] OK: {len(staged)} staged file(s) within "
              f"current lane '{current_agent_id}' pathspec")
        sys.exit(0)

    # Gap #55: dedicated handling for the orphan-file-only refusal. When the
    # ONLY violation is undeclared (excess) files - no sibling absorption,
    # no cross-claim - emit the `fail-undeclared-file-staged` verdict and
    # honour the gap55-rebuttal marker.
    if excess and not sibling_absorbed and not cross_claimed and not gap55_disable:
        if gap55_reason:
            print(f"[r36-pathspec] (Gap #55) orphan-file rebuttal accepted: "
                  f"{gap55_reason[:200]}")
            print(f"[r36-pathspec] OK: {len(staged)} staged file(s) within "
                  f"current lane '{current_agent_id}' pathspec "
                  f"(orphan-file acknowledged)")
            sys.exit(0)
        print(f"[r36-pathspec] REFUSED (Gap #55): fail-undeclared-file-staged")
        print(f"  declaration : {pathspec_file}")
        print(f"  current lane: {current_agent_id}")
        print(f"  undeclared staged file(s) (in NO live agent's pathspec):")
        for f in excess:
            print(f"    + {f}")
        print("")
        print("  Gap #55 - undeclared-file (orphan) staging discipline.")
        print("  Files staged but not registered in any LIVE (non-expired)")
        print("  lane's pathspec slip past Gap #41's cross-claim detection")
        print("  because they have no owner to be compared against. Either:")
        print("    * unstage the file(s), or")
        print("    * register your lane's intent (preferred):")
        print("      `python3 tools/agent-pathspec-register.py register --lane <id> --files <comma-list>`")
        print("    * or, if the staging is operator-intentional, add a")
        print("      non-empty marker:")
        print("      <!-- gap55-rebuttal: <reason up to 200 chars> -->")
        print("      (the broader <!-- r36-rebuttal: ... --> also silences this)")
        sys.exit(1)

    # Hard-fail on sibling absorption (the FIX-C anchor case).
    print(f"[r36-pathspec] REFUSED: staged files absorb sibling-lane work or "
          f"exceed the current lane's declared pathspec.")
    print(f"  declaration : {pathspec_file}")
    print(f"  current lane: {current_agent_id}")
    if sibling_absorbed:
        print(f"  sibling-lane files in staged set (NOT declared by current lane):")
        for f in sibling_absorbed:
            # Annotate which sibling lane owns each file.
            owners = sorted(
                aid for aid, declared in live_agents
                if aid != current_agent_id and f in declared
            )
            owner_str = f" [owned by: {', '.join(owners)}]" if owners else ""
            print(f"    + {f}{owner_str}")
    if excess:
        print(f"  undeclared staged file(s) (in no live agent's pathspec):")
        for f in excess:
            print(f"    + {f}")
    if cross_claimed:
        print(f"  cross-claimed file(s) (Gap #41 - in current lane AND >=1 sibling):")
        for f in cross_claimed:
            others = [o for o in file_ownership[f] if o != current_agent_id]
            print(f"    + {f}  [also claimed by: {', '.join(others)}]")
    print("")
    print("  Rule 36 - parallel-worktree-commit-pathspec-discipline.")
    print("  Gap #41 - per-file cross-lane pollution detection.")
    print("  In a shared worktree, stage by explicit per-file pathspec; do not")
    print("  use `git add -A` / `git add .` / `git add <dir>/`. Either:")
    print("    * unstage files outside the current lane's pathspec, or")
    print("    * add them to the current lane's entry in")
    print("      .auditooor/agent_pathspec.json (intentional widening), or")
    print("    * coordinate with the sibling lane to unregister conflicting")
    print("      intents (Gap #41), or")
    print("    * for an intentional sweep, put a non-empty marker in the commit")
    print("      message:  <!-- r36-rebuttal: <reason up to 200 chars> -->")
    print("      (use <!-- gap41-rebuttal: ... --> for cross-claim only)")
    sys.exit(1)

# LEGACY MODE: no current-agent-id env hook OR the env var did not match a
# live lane. Fall back to staged ⊆ union(live agents). Optionally strict-fail
# under R36_STRICT_NO_LANE_ID=1.
if strict_no_lane_id:
    print(f"[r36-pathspec] REFUSED: R36_STRICT_NO_LANE_ID=1 and no current "
          f"lane identified via R36_CURRENT_AGENT_ID / R55_CURRENT_AGENT_ID.")
    print(f"  live agents : {', '.join(aid for aid, _ in live_agents)}")
    print(f"  To enforce per-lane discipline, export R36_CURRENT_AGENT_ID=<lane-id>")
    print(f"  matching a live entry in {pathspec_file}.")
    sys.exit(1)

excess = sorted(
    f for f in staged
    if f not in live_union and not _is_system_wide(f, extra_patterns)
)
if not excess:
    live_ids = [aid for aid, _ in live_agents]
    if current_agent_id:
        # Env was set but did not match a live lane. Warn so operators notice.
        print(f"[r36-pathspec] WARNING: R36_CURRENT_AGENT_ID='{current_agent_id}' "
              f"does not match any live lane; falling back to union mode. "
              f"Live lanes: {', '.join(live_ids)}")
    print(f"[r36-pathspec] OK (legacy union mode): {len(staged)} staged "
          f"file(s) within declared pathspec ({', '.join(live_ids)})")
    sys.exit(0)

# Gap #55: legacy-mode orphan-file rebuttal honour. When the only violation
# is undeclared (orphan) files in legacy mode, the gap55-rebuttal marker
# silences the refusal just like in current-lane mode.
if gap55_reason and not gap55_disable:
    print(f"[r36-pathspec] (Gap #55) orphan-file rebuttal accepted: "
          f"{gap55_reason[:200]}")
    print(f"[r36-pathspec] OK (legacy union mode): {len(staged)} staged "
          f"file(s) (orphan-file acknowledged)")
    sys.exit(0)

print(f"[r36-pathspec] REFUSED (Gap #55): fail-undeclared-file-staged")
print(f"  declaration : {pathspec_file}")
print(f"  live agents : {', '.join(aid for aid, _ in live_agents)}")
if current_agent_id:
    print(f"  R36_CURRENT_AGENT_ID='{current_agent_id}' did not match any "
          f"live lane; legacy union mode applied.")
print("  undeclared staged file(s) (in NO live agent's pathspec):")
for f in excess:
    print(f"    + {f}")
print("")
print("  Rule 36 - parallel-worktree-commit-pathspec-discipline.")
print("  Gap #55 - undeclared-file (orphan) staging discipline.")
print("  In a shared worktree, stage by explicit per-file pathspec; do not")
print("  use `git add -A` / `git add .` / `git add <dir>/`. Either:")
print("    * unstage the undeclared files, or")
print("    * add them to .auditooor/agent_pathspec.json if they are yours, or")
print("    * for an intentional sweep, put a non-empty marker in the commit")
print("      message:  <!-- r36-rebuttal: <reason up to 200 chars> -->")
print("      (or the narrower <!-- gap55-rebuttal: ... --> for orphan only)")
sys.exit(1)
PYEOF
exit $?
