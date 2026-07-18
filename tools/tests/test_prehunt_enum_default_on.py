"""Regression: pre-hunt ENUMERATION is DEFAULT-ON (opt-OUT), not default-off.

The pre-hunt enumeration steers the hunt toward the highest-value undriven
(in-scope unit x impact-frame) cells. It used to be DEFAULT-OFF (opt-in via
AUDITOOOR_PREHUNT_MATRIX=1), so the default pipeline hunted UNGUIDED by
prioritization. This test pins the flip to default-ON:

  - AUDITOOOR_PREHUNT_MATRIX UNSET  -> enumeration RUNS   (default-on)
  - AUDITOOOR_PREHUNT_MATRIX=0      -> enumeration SKIPPED (explicit opt-out)

It checks BOTH gating sites:
  1. `hunt-scoped` entry, gated by the make var `_PREHUNT_ENUM_ON` (line ~4605),
     asserted via `make -n hunt-scoped` dispatch of `_hunt-prehunt-enum`.
  2. `audit-pipeline-full` STEP 2.9, gated by a shell `if` on
     AUDITOOOR_PREHUNT_MATRIX (line ~6897), asserted by re-evaluating the exact
     condition text parsed out of the Makefile.

AUDITOOOR_PLANE_DRAIN behavior is intentionally NOT changed (still opt-in).
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
MAKEFILE = REPO / "Makefile"


def _make_n_hunt_scoped(env_overrides):
    env = dict(os.environ)
    env.pop("AUDITOOOR_PREHUNT_MATRIX", None)
    env.update(env_overrides)
    cmd = ["make", "-n", "hunt-scoped", "WS=/tmp/__prehunt_enum_test_ws__"]
    gt = shutil.which("gtimeout") or shutil.which("timeout")
    if gt:
        cmd = [gt, "30"] + cmd
    p = subprocess.run(cmd, cwd=REPO, env=env, capture_output=True, text=True)
    return p.stdout + p.stderr


def _dispatches_prehunt_enum(output):
    # The actual sub-target dispatch (not a comment line starting with '#').
    for line in output.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if "_hunt-prehunt-enum" in line:
            return True
    return False


def test_hunt_scoped_default_on_unset():
    out = _make_n_hunt_scoped({})
    assert _dispatches_prehunt_enum(out), (
        "hunt-scoped with AUDITOOOR_PREHUNT_MATRIX UNSET must dispatch "
        "_hunt-prehunt-enum (default-ON)"
    )


def test_hunt_scoped_opt_out_zero():
    out = _make_n_hunt_scoped({"AUDITOOOR_PREHUNT_MATRIX": "0"})
    assert not _dispatches_prehunt_enum(out), (
        "hunt-scoped with AUDITOOOR_PREHUNT_MATRIX=0 must NOT dispatch "
        "_hunt-prehunt-enum (explicit opt-out)"
    )


def test_prehunt_enum_on_var_uses_or_default_1():
    """The _PREHUNT_ENUM_ON var must default the matrix flag to 1 when unset."""
    text = MAKEFILE.read_text()
    m = re.search(r"^_PREHUNT_ENUM_ON\s*:?=\s*(.+)$", text, re.MULTILINE)
    assert m, "_PREHUNT_ENUM_ON assignment not found"
    body = m.group(1)
    assert "$(or $(AUDITOOOR_PREHUNT_MATRIX),1)" in body, (
        "unset AUDITOOOR_PREHUNT_MATRIX must default to 1 via $(or ...,1); "
        f"got: {body}"
    )
    # PLANE_DRAIN must stay plain opt-in (no ,1 default).
    assert "$(or $(AUDITOOOR_PLANE_DRAIN)" not in body, (
        "AUDITOOOR_PLANE_DRAIN must remain opt-in (no default-on)"
    )


def _extract_step29_condition(text):
    # Find the STEP 2.9 shell `if [ ... ]; then` line inside audit-pipeline-full.
    idx = text.find("STEP 2.9/8: pre-hunt ENUMERATION")
    assert idx != -1, "STEP 2.9 pipeline block not found"
    tail = text[idx:]
    m = re.search(r"@if (.+?); then \\", tail)
    assert m, "STEP 2.9 `if ...; then` condition not found"
    return m.group(1)


def _eval_step29(cond_make, matrix_value):
    """Expand the Make-level $(AUDITOOOR_...) refs then eval the shell test."""
    val = "" if matrix_value is None else matrix_value
    cond = cond_make.replace("$(AUDITOOOR_PREHUNT_MATRIX)", val)
    # Run through /bin/sh exactly as the recipe would.
    p = subprocess.run(
        ["/bin/sh", "-c", f'if {cond}; then echo RUNS; else echo SKIPPED; fi'],
        capture_output=True, text=True,
    )
    return p.stdout.strip()


def test_pipeline_step29_default_on_unset():
    cond = _extract_step29_condition(MAKEFILE.read_text())
    # default-on: unset must NOT require -n "$(...)" presence (that was the bug).
    assert '-n "$(AUDITOOOR_PREHUNT_MATRIX)"' not in cond, (
        "STEP 2.9 must not gate on the flag being SET (that is default-off)"
    )
    assert _eval_step29(cond, None) == "RUNS", (
        "STEP 2.9 with matrix UNSET must RUN (default-on)"
    )


def test_pipeline_step29_opt_out_zero():
    cond = _extract_step29_condition(MAKEFILE.read_text())
    assert _eval_step29(cond, "0") == "SKIPPED"
    assert _eval_step29(cond, "false") == "SKIPPED"
    assert _eval_step29(cond, "no") == "SKIPPED"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
