#!/usr/bin/env python3
"""
tools/agents-md-sync-check.py
Hash-pin verifier: confirms all per-tool sentinel files contain an
up-to-date `# AGENTS.md ref: <sha>` marker that matches the SHA-256 of
the AGENTS.md L25-L31 canonical section.

Usage:
  python3 tools/agents-md-sync-check.py --check   # exits 0 (in-sync) or 1 (drift)
  python3 tools/agents-md-sync-check.py --update  # rewrites all sentinel markers

Wired into `make agents-md-sync` (advisory under `make docs-check` with STRICT=1
for hard-fail; warn-only otherwise).
"""

import argparse
import hashlib
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (relative to repo root)
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_MD = REPO_ROOT / "AGENTS.md"

SENTINEL_FILES = [
    REPO_ROOT / ".cursorrules",
    REPO_ROOT / ".windsurfrules",
    REPO_ROOT / ".aider.conf.yml",
    REPO_ROOT / ".github" / "copilot-instructions.md",
    REPO_ROOT / ".kimi" / "AGENTS.md",
]

# The marker line pattern inside each sentinel
MARKER_PREFIX = "# AGENTS.md ref:"
MARKER_PATTERN = re.compile(r"^# AGENTS\.md ref:\s*(\S+)", re.MULTILINE)

# ---------------------------------------------------------------------------
# Canonical section extraction + hashing
# ---------------------------------------------------------------------------
SECTION_HEADER = "## L25-L31 doctrine for provider-agnostic agents"


def extract_canonical_section(agents_text: str) -> str:
    """Extract the L25-L31 section from AGENTS.md for hashing.

    Returns the text from the section header to the end of the file
    (or to the next top-level ## header, whichever comes first after
    the section content).
    """
    idx = agents_text.find(SECTION_HEADER)
    if idx == -1:
        raise ValueError(
            f"Could not find canonical section '{SECTION_HEADER}' in AGENTS.md. "
            "Run `make agents-md-sync` after adding the L25-L31 section."
        )
    return agents_text[idx:]


def compute_agents_sha(agents_text: str) -> str:
    """Return the first 16 hex chars of the SHA-256 of the canonical section."""
    section = extract_canonical_section(agents_text)
    return hashlib.sha256(section.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Sentinel file operations
# ---------------------------------------------------------------------------
def get_sentinel_sha(sentinel_text: str):
    """Return the sha recorded in the sentinel, or None if absent."""
    m = MARKER_PATTERN.search(sentinel_text)
    if m:
        recorded = m.group(1)
        if recorded == "PLACEHOLDER":
            return None
        return recorded
    return None


def update_sentinel(path: Path, new_sha: str) -> bool:
    """Rewrite the AGENTS.md ref marker in the sentinel file.

    Returns True if the file was changed, False if it was already correct.
    """
    text = path.read_text()
    new_marker = f"{MARKER_PREFIX} {new_sha}"

    # Replace existing marker line
    if MARKER_PATTERN.search(text):
        new_text = MARKER_PATTERN.sub(new_marker, text, count=1)
    else:
        # Insert as the second line (after the tool-name comment or first line)
        lines = text.splitlines(keepends=True)
        lines.insert(1, new_marker + "\n")
        new_text = "".join(lines)

    if new_text == text:
        return False
    path.write_text(new_text)
    return True


# ---------------------------------------------------------------------------
# Main check / update logic
# ---------------------------------------------------------------------------
def run_check(agents_sha: str) -> int:
    """Check all sentinels. Returns 0 (all in sync) or 1 (drift detected)."""
    all_ok = True
    for sentinel in SENTINEL_FILES:
        if not sentinel.exists():
            print(f"[agents-md-sync] MISSING  {sentinel.relative_to(REPO_ROOT)}")
            all_ok = False
            continue

        recorded = get_sentinel_sha(sentinel.read_text())
        rel = sentinel.relative_to(REPO_ROOT)
        if recorded is None:
            print(f"[agents-md-sync] NO-MARKER {rel}  (PLACEHOLDER or absent)")
            all_ok = False
        elif recorded != agents_sha:
            print(
                f"[agents-md-sync] DRIFT    {rel}  "
                f"recorded={recorded}  current={agents_sha}"
            )
            all_ok = False
        else:
            print(f"[agents-md-sync] OK       {rel}  sha={agents_sha}")

    if all_ok:
        print(f"[agents-md-sync] All {len(SENTINEL_FILES)} sentinels in sync.")
        return 0
    print(
        "[agents-md-sync] Drift detected. "
        "Run `python3 tools/agents-md-sync-check.py --update` to fix."
    )
    return 1


def run_update(agents_sha: str) -> int:
    """Update all sentinels with the current sha. Returns 0 always."""
    for sentinel in SENTINEL_FILES:
        if not sentinel.exists():
            print(f"[agents-md-sync] SKIP (missing) {sentinel.relative_to(REPO_ROOT)}")
            continue
        changed = update_sentinel(sentinel, agents_sha)
        rel = sentinel.relative_to(REPO_ROOT)
        if changed:
            print(f"[agents-md-sync] UPDATED  {rel}  -> sha={agents_sha}")
        else:
            print(f"[agents-md-sync] ALREADY-OK {rel}  sha={agents_sha}")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify or update AGENTS.md ref hash pins in per-tool sentinel files."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--check",
        action="store_true",
        help="Check all sentinels; exit 1 on drift.",
    )
    group.add_argument(
        "--update",
        action="store_true",
        help="Rewrite all sentinel markers with the current AGENTS.md sha.",
    )
    args = parser.parse_args()

    if not AGENTS_MD.exists():
        print(f"[agents-md-sync] ERROR: AGENTS.md not found at {AGENTS_MD}", file=sys.stderr)
        return 2

    agents_text = AGENTS_MD.read_text()
    try:
        agents_sha = compute_agents_sha(agents_text)
    except ValueError as exc:
        print(f"[agents-md-sync] ERROR: {exc}", file=sys.stderr)
        return 2

    if args.check:
        return run_check(agents_sha)
    if args.update:
        return run_update(agents_sha)
    return 0  # unreachable


if __name__ == "__main__":
    sys.exit(main())
