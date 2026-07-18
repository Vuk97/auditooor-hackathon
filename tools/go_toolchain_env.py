#!/usr/bin/env python3
"""go_toolchain_env.py - shared helper: honor a Go workspace's pinned toolchain.

WHY (root-caused NUVA 2026-07-08 / re-hit 2026-07-12): a Go workspace can pin an exact
toolchain in its `go.work`/`go.mod` (`toolchain go1.25.8`, or a 3-part `go 1.25.8`). When
the auditooor Go engines / harness runners / coverage tools shell out to `go build` /
`go test` WITHOUT honoring that pin, Go uses the host default (e.g. go1.26.2). If a dep only
compiles under the pinned toolchain (NUVA: `bytedance/sonic` needs go1.25.8 - `undefined:
GoMapIterator` under go1.26.2, a runtime internal changed in 1.26), the build SILENTLY
`build_failed` / degrades: the workspace looks hollow and coverage regresses. This is the
recurring "GOTOOLCHAIN suspected" issue.

FIX (generic, workspace-driven - never hardcode a version): parse the target module's
`go.work`/`go.mod` for a `toolchain goX.Y.Z` directive (else a 3-part `go X.Y.Z` line) and
set `env["GOTOOLCHAIN"]` to that exact pin so Go uses the cached/installed pinned toolchain
(offline once cached; loosen GOPROXY on demand so it can be fetched). An already-set
GOTOOLCHAIN in the incoming env is RESPECTED (never clobbered).

Public API:
  workspace_go_toolchain(cwd) -> str        # '' if none pinned
  toolchain_available(tc) -> bool           # cached/installed/ambient?
  apply_go_toolchain(env, cwd, ...) -> str  # mutate env in place, return the pin ('' if none)
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

# A `toolchain goX.Y[.Z]` directive is an explicit pin (valid GOTOOLCHAIN name).
_TOOLCHAIN_RE = re.compile(r"^\s*toolchain\s+(go\d+\.\d+(?:\.\d+)?)", re.M)
# ONLY a 3-part `go X.Y.Z` yields a valid GOTOOLCHAIN name (goX.Y.Z); a 2-part `go X.Y` is a
# language MINIMUM, not a toolchain pin, and `goX.Y` is a malformed GOTOOLCHAIN that errors
# the binary - so require the patch component.
_GO_DIRECTIVE_RE = re.compile(r"^\s*go\s+(\d+\.\d+\.\d+)", re.M)


def workspace_go_toolchain(cwd) -> str:
    """Return the exact Go toolchain the workspace PINS, or '' if none.

    Walks up to 8 parents looking for `go.work` then `go.mod`; a `toolchain goX.Y.Z`
    directive wins, else a 3-part `go X.Y.Z` line -> `goX.Y.Z`. Never hardcodes a version -
    the pin is read from the workspace itself so it is generic to every Go/cosmos-sdk ws."""
    for name in ("go.work", "go.mod"):
        d = Path(cwd)
        for _ in range(8):
            f = d / name
            if f.exists():
                try:
                    txt = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    break
                m = _TOOLCHAIN_RE.search(txt)
                if m:
                    return m.group(1)
                if name == "go.mod":
                    g = _GO_DIRECTIVE_RE.search(txt)
                    if g:
                        return "go" + g.group(1)
                break
            if d.parent == d:
                break
            d = d.parent
    return ""


def toolchain_available(tc: str) -> bool:
    """True if the pinned toolchain `tc` is cached/installed locally or is the ambient one.

    Lets callers decide whether GOPROXY=off can supply it (else loosen the proxy to fetch it)
    rather than degrading silently."""
    if not tc:
        return True
    home = Path(os.path.expanduser("~"))
    if list((home / "go" / "pkg" / "mod" / "golang.org").glob(f"toolchain@*{tc[2:]}*")):
        return True
    if (home / "sdk" / tc).exists():
        return True
    try:
        out = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=20)
        return tc in out.stdout
    except Exception:
        return False


def apply_go_toolchain(env, cwd, *, loosen_goproxy_if_needed: bool = True,
                       log_prefix: str = "go") -> str:
    """Set env['GOTOOLCHAIN'] to the workspace pin (if any) so `go build`/`go test` honor it.

    - RESPECTS an already-set GOTOOLCHAIN (never clobbers an explicit caller/operator choice).
    - If no toolchain is pinned, the env is left BYTE-IDENTICAL (no key added).
    - If the pin is not available offline and GOPROXY is off, optionally loosen GOPROXY so the
      toolchain can be fetched (loud WARN) instead of a silent build_failed / degrade.

    Mutates `env` in place; returns the applied pin ('' when none)."""
    if env.get("GOTOOLCHAIN"):
        # Explicit caller/operator choice - honor it verbatim.
        return env["GOTOOLCHAIN"]
    tc = workspace_go_toolchain(cwd)
    if not tc:
        return ""
    env["GOTOOLCHAIN"] = tc
    if loosen_goproxy_if_needed and env.get("GOPROXY") == "off" and not toolchain_available(tc):
        print(f"[{log_prefix}] WARN pinned toolchain {tc} not available offline; loosening "
              f"GOPROXY to fetch it (was off) so the Go run is not silently build_failed / "
              f"degraded - install {tc} locally to stay fully offline", file=sys.stderr)
        env["GOPROXY"] = "https://proxy.golang.org,direct"
    return tc
