#!/usr/bin/env python3
"""Helper to register / unregister / refresh a per-lane entry in
`.auditooor/agent_pathspec.json` (the R36 + R55 declaration file).

Background
----------
R36 (`tools/git-hooks/pre-commit-pathspec-discipline.sh`) and R55
(`tools/git-hooks/pre-destructive-op-sibling-check.sh`) both read
`.auditooor/agent_pathspec.json` to know which files each in-flight
lane owns. Without that file, R55 runs INERT (no sibling attribution
possible) and R36 is a no-op. This helper makes lane registration a
one-line operation so future lane spawns can register cleanly:

    python3 tools/agent-pathspec-register.py \
        --lane lane-WWWWW \
        --files tools/foo.py,tools/tests/test_foo.py \
        --ttl 7200

Schema (per R36 / R55 hook source):

    {
      "agents": [
        {
          "agent_id": "lane-X",
          "files": ["tools/foo.py", ...],
          "expires_at": "2026-05-23T17:19:06Z"
        }
      ]
    }

The hooks compare staged / modified file paths to `files` entries via
EXACT string match. Glob patterns like `dir/**` DO NOT match anything,
so this helper rejects them at registration time. Enumerate concrete
files instead. See docs/AGENT_PATHSPEC_SCHEMA.md.

Subcommands
-----------
- `register` (default): add or replace an agent's entry.
- `unregister`: drop an agent entirely.
- `refresh`: bump `expires_at` on an existing entry without touching files.
- `list`: print all registered agents and their TTL remaining.
- `prune`: drop all entries whose `expires_at` is in the past.

Concurrency
-----------
The helper holds an EXCLUSIVE fcntl lock on a sidecar lockfile
(`<pathspec>.lock`) for the full read-modify-write cycle. This is the
POSIX `flock(LOCK_EX)` primitive (advisory but mandatory across well-
behaved cooperating processes - everything that goes through this helper
participates in the same lock domain). Writes still use the atomic
`os.replace` pattern so reader-only callers (the R36 / R55 shell hooks,
which do NOT take the lock) see a consistent snapshot.

The locking model:

  1. Open `<pathspec>.lock` (created if missing, permissions 0644).
  2. `fcntl.flock(fd, LOCK_EX)` - blocks until exclusive access granted.
  3. Read the pathspec JSON.
  4. Mutate in memory.
  5. Atomic write (`<file>.tmp.<pid>` + `os.replace`).
  6. Release lock via `flock(fd, LOCK_UN)` + close.

The lock is held for the duration of one register / unregister / refresh
/ prune. Pure `list` ops (read-only) skip the lock entirely - they accept
the small risk of reading a half-written file, which is impossible anyway
because all writes are atomic-rename.

Stale lock recovery: `flock` releases automatically when the holding
process exits (POSIX guarantee). There is no recovery code needed for
crashed writers. If a writer hangs for >LOCK_TIMEOUT_SECONDS (default
30s), `_acquire_lock` exits non-zero rather than blocking indefinitely.

The previous mtime-based optimistic-retry implementation was RACY: two
writers could both see matching mtime within the same sub-second tick,
both `os.replace`, and the second write would silently clobber the first
(both reported `exit 0`). See `tools/tests/test_agent_pathspec_register.py`
test `test_concurrent_registers_all_survive` for the regression case.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import fcntl
import json
import os
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

DEFAULT_PATHSPEC_REL = ".auditooor/agent_pathspec.json"
DEFAULT_TTL_SECONDS = 7200  # 2 hours per R36 anchor
LOCK_TIMEOUT_SECONDS = 30   # max wait for exclusive lock; envconfig below
LOCK_SUFFIX = ".lock"


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(text: str) -> datetime | None:
    if not text:
        return None
    s = text.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _read_json(pathspec_file: Path) -> dict[str, Any]:
    """Read + validate the pathspec JSON. Caller holds the lock (or doesn't
    care - the file is always atomic-rename-written, so a half-write is
    structurally impossible)."""
    if not pathspec_file.exists():
        return {"agents": []}
    try:
        with pathspec_file.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"[agent-pathspec] ERROR: cannot read/parse {pathspec_file}: {exc}",
            file=sys.stderr,
        )
        sys.exit(2)
    if not isinstance(data, dict):
        print(
            f"[agent-pathspec] ERROR: {pathspec_file} top-level must be a JSON object",
            file=sys.stderr,
        )
        sys.exit(2)
    data.setdefault("agents", [])
    if not isinstance(data["agents"], list):
        print(
            f"[agent-pathspec] ERROR: {pathspec_file} `agents` must be a list",
            file=sys.stderr,
        )
        sys.exit(2)
    return data


def _atomic_write(pathspec_file: Path, data: dict[str, Any]) -> None:
    """Write atomically via tmp + rename. Caller MUST hold the lock."""
    pathspec_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = pathspec_file.with_suffix(
        pathspec_file.suffix + f".tmp.{os.getpid()}"
    )
    payload = json.dumps(data, indent=2, sort_keys=False) + "\n"
    tmp.write_text(payload, encoding="utf-8")
    os.replace(tmp, pathspec_file)


@contextlib.contextmanager
def _exclusive_lock(pathspec_file: Path,
                    timeout: int = LOCK_TIMEOUT_SECONDS) -> Iterator[None]:
    """Hold an exclusive fcntl.flock on a sidecar lockfile for the body.

    The lock is auto-released on process exit (POSIX guarantee), so crashed
    writers cannot leave the lock held. If acquisition takes longer than
    `timeout` seconds, exit non-zero rather than block indefinitely.

    Read-only callers (`list`) do NOT use this; they accept the small
    cost of reading a possibly-stale snapshot, which is consistent because
    writers always atomic-rename.
    """
    lockfile = pathspec_file.with_suffix(pathspec_file.suffix + LOCK_SUFFIX)
    lockfile.parent.mkdir(parents=True, exist_ok=True)
    # Open with O_CREAT so the lockfile is created on first use without
    # racing with another lock-attempt's create-if-missing.
    fd = os.open(str(lockfile), os.O_RDWR | os.O_CREAT, 0o644)
    deadline = time.monotonic() + max(1, int(timeout))
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                    raise
                if time.monotonic() >= deadline:
                    print(
                        f"[agent-pathspec] ERROR: could not acquire "
                        f"{lockfile} within {timeout}s; another writer may "
                        f"be hung",
                        file=sys.stderr,
                    )
                    sys.exit(4)
                time.sleep(0.05)
        try:
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _locked_rmw(pathspec_file: Path, mutator,
                lock_timeout: int = LOCK_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Read-modify-write under exclusive lock. Replaces the legacy
    `_with_retry` mtime-based optimistic loop that allowed silent data
    loss when two writers happened within the same mtime tick."""
    with _exclusive_lock(pathspec_file, timeout=lock_timeout):
        data = _read_json(pathspec_file)
        mutator(data)
        _atomic_write(pathspec_file, data)
    return data


# Back-compat alias for any external callers that may import it.
def _with_retry(pathspec_file: Path, mutator,
                max_attempts: int = 3) -> dict[str, Any]:
    """Deprecated shim. Forwards to `_locked_rmw`; `max_attempts` is
    ignored because we no longer retry (the exclusive lock guarantees
    we never need to)."""
    return _locked_rmw(pathspec_file, mutator)


def _normalize_files(raw: str | list[str]) -> list[str]:
    if isinstance(raw, list):
        items = raw
    else:
        # Comma-separated, with optional whitespace.
        items = [s.strip() for s in raw.split(",")]
    cleaned = []
    seen = set()
    for item in items:
        item = item.strip()
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        cleaned.append(item)
    return cleaned


def _register_files_arg(args: argparse.Namespace) -> str | list[str]:
    pathspec_entries = getattr(args, "pathspec_entries", None) or []
    files = getattr(args, "files", None)
    if pathspec_entries:
        if files:
            return [files, *pathspec_entries]
        return pathspec_entries
    return files or ""


def _validate_files(files: list[str]) -> None:
    """Reject glob-like entries because R36/R55 compare via exact match."""
    glob_chars = ("*", "?", "[")
    for f in files:
        if any(c in f for c in glob_chars):
            raise ValueError(
                f"[agent-pathspec] ERROR: '{f}' contains glob characters. "
                f"R36/R55 hooks use EXACT string match; enumerate concrete "
                f"files instead."
            )


def _lock_timeout(args: argparse.Namespace) -> int:
    """Extract --lock-timeout from args, defaulting safely if absent."""
    return int(getattr(args, "lock_timeout", LOCK_TIMEOUT_SECONDS))


def cmd_register(args: argparse.Namespace) -> int:
    files = _normalize_files(_register_files_arg(args))
    if not files:
        print("[agent-pathspec] ERROR: --files or --pathspec must list at least one path",
              file=sys.stderr)
        return 2
    try:
        _validate_files(files)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    ttl = max(60, int(args.ttl))
    expires_at = _iso_utc(_now() + timedelta(seconds=ttl))
    entry = {
        "agent_id": args.lane,
        "files": files,
        "expires_at": expires_at,
    }
    if args.lane_title:
        entry["lane_title"] = args.lane_title
    if args.notes:
        entry["notes"] = args.notes

    def mutator(data: dict[str, Any]) -> None:
        agents = data["agents"]
        agents[:] = [a for a in agents
                     if str(a.get("agent_id", "")) != args.lane]
        agents.append(entry)
        # Maintenance metadata.
        data["_populated_at"] = _iso_utc(_now())

    pathspec_file = Path(args.pathspec_file)
    _locked_rmw(pathspec_file, mutator,
                lock_timeout=_lock_timeout(args))
    print(
        f"[agent-pathspec] registered {args.lane}: {len(files)} file(s), "
        f"expires {expires_at}"
    )
    return 0


def cmd_unregister(args: argparse.Namespace) -> int:
    found = [False]

    def mutator(data: dict[str, Any]) -> None:
        agents = data["agents"]
        before = len(agents)
        agents[:] = [a for a in agents
                     if str(a.get("agent_id", "")) != args.lane]
        if len(agents) < before:
            found[0] = True

    pathspec_file = Path(args.pathspec_file)
    _locked_rmw(pathspec_file, mutator,
                lock_timeout=_lock_timeout(args))
    if found[0]:
        print(f"[agent-pathspec] unregistered {args.lane}")
        return 0
    print(f"[agent-pathspec] {args.lane} not present; no-op", file=sys.stderr)
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    ttl = max(60, int(args.ttl))
    new_expires = _iso_utc(_now() + timedelta(seconds=ttl))
    touched = [False]

    def mutator(data: dict[str, Any]) -> None:
        for a in data["agents"]:
            if str(a.get("agent_id", "")) == args.lane:
                a["expires_at"] = new_expires
                touched[0] = True

    pathspec_file = Path(args.pathspec_file)
    _locked_rmw(pathspec_file, mutator,
                lock_timeout=_lock_timeout(args))
    if touched[0]:
        print(f"[agent-pathspec] refreshed {args.lane} -> {new_expires}")
        return 0
    print(f"[agent-pathspec] {args.lane} not present; cannot refresh",
          file=sys.stderr)
    return 1


def cmd_list(args: argparse.Namespace) -> int:
    # Read-only callers skip the lock - atomic-rename writes guarantee
    # that any snapshot we read is internally consistent.
    pathspec_file = Path(args.pathspec_file)
    data = _read_json(pathspec_file)
    now = _now()
    agents = data.get("agents", [])
    if not agents:
        print("[agent-pathspec] no agents registered")
        return 0
    print(f"[agent-pathspec] {len(agents)} agent(s) in {pathspec_file}")
    for a in agents:
        aid = a.get("agent_id", "<unnamed>")
        files = a.get("files", [])
        exp = _parse_ts(a.get("expires_at", ""))
        if exp is None:
            status = "no-expiry"
        elif exp <= now:
            status = f"EXPIRED ({_iso_utc(exp)})"
        else:
            remaining = exp - now
            status = (f"live, {int(remaining.total_seconds() // 60)} min "
                      f"remaining (until {_iso_utc(exp)})")
        title = a.get("lane_title", "")
        title_str = f" [{title}]" if title else ""
        print(f"  {aid}{title_str}: {len(files)} file(s), {status}")
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    pruned = [0]

    def mutator(data: dict[str, Any]) -> None:
        now = _now()
        kept = []
        for a in data["agents"]:
            exp = _parse_ts(a.get("expires_at", ""))
            if exp is None or exp > now:
                kept.append(a)
            else:
                pruned[0] += 1
        data["agents"] = kept

    pathspec_file = Path(args.pathspec_file)
    _locked_rmw(pathspec_file, mutator,
                lock_timeout=_lock_timeout(args))
    print(f"[agent-pathspec] pruned {pruned[0]} expired entrie(s)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-pathspec-register.py",
        description=(
            "Register / unregister / refresh per-lane pathspec entries in "
            ".auditooor/agent_pathspec.json (consumed by R36 + R55 git hooks)."
        ),
    )
    p.add_argument(
        "--pathspec-file",
        default=DEFAULT_PATHSPEC_REL,
        help=(
            "Path to the pathspec JSON (default: %(default)s, relative to cwd)."
        ),
    )
    p.add_argument(
        "--lock-timeout",
        type=int,
        default=LOCK_TIMEOUT_SECONDS,
        help=(
            "Max seconds to wait for the exclusive lock before exiting "
            "non-zero (default: %(default)s). Read-only `list` ignores this."
        ),
    )
    sub = p.add_subparsers(dest="cmd")

    # register (default)
    reg = sub.add_parser("register", help="Add or replace a lane entry.")
    reg.add_argument("--lane", "--agent-id", dest="lane", required=True,
                     help="Lane id, e.g. 'lane-WWWWW'.")
    reg.add_argument("--files",
                     help="Comma-separated list of file paths.")
    reg.add_argument(
        "--pathspec",
        dest="pathspec_entries",
        action="append",
        default=[],
        help=(
            "Lane-brief compatibility alias; may be repeated. Equivalent "
            "to entries in --files."
        ),
    )
    reg.add_argument("--ttl", "--expires-in", dest="ttl", type=int, default=DEFAULT_TTL_SECONDS,
                     help="Seconds until expiry (default: 7200 = 2h).")
    reg.add_argument("--lane-title", default="",
                     help="Optional human-readable lane title.")
    reg.add_argument("--notes", default="",
                     help="Optional free-form notes for the entry.")
    reg.set_defaults(func=cmd_register)

    unreg = sub.add_parser("unregister", help="Remove a lane entry.")
    unreg.add_argument("--lane", required=True)
    unreg.set_defaults(func=cmd_unregister)

    refr = sub.add_parser("refresh",
                          help="Bump expires_at on an existing lane.")
    refr.add_argument("--lane", required=True)
    refr.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS)
    refr.set_defaults(func=cmd_refresh)

    lst = sub.add_parser("list", help="List all registered lanes + TTL state.")
    lst.set_defaults(func=cmd_list)

    pru = sub.add_parser("prune", help="Drop all expired entries.")
    pru.set_defaults(func=cmd_prune)

    # Convenience: bare invocation without a subcommand defaults to `register`
    # when --lane is given.
    p.add_argument("--lane", "--agent-id", dest="lane", help=argparse.SUPPRESS)
    p.add_argument("--files", help=argparse.SUPPRESS)
    p.add_argument(
        "--pathspec",
        dest="pathspec_entries",
        action="append",
        default=[],
        help=argparse.SUPPRESS,
    )
    p.add_argument("--ttl", "--expires-in", dest="ttl", type=int, default=DEFAULT_TTL_SECONDS,
                   help=argparse.SUPPRESS)
    p.add_argument("--lane-title", default="", help=argparse.SUPPRESS)
    p.add_argument("--notes", default="", help=argparse.SUPPRESS)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd is None:
        if args.lane and (args.files or getattr(args, "pathspec_entries", None)):
            return cmd_register(args)
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
