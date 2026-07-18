from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "scope-oos-dispatch-guard.py"


SEI_LIKE_SCOPE = """\
# Scope

## In scope

- `giga/executor` - the Giga execution engine.

## Out of scope

The following are OUT of scope and not eligible for rewards:

- Autobahn consensus is OUT of scope.
- All code in `giga` packages other than `giga/executor` is out of scope.
- The EVMone backend is OUT of scope.
"""


def _mk_ws(root: Path) -> None:
    for d in ("giga/executor", "giga/deps", "autobahn/consensus",
              "evmone/backend", "x/evm/keeper"):
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "giga/executor/exec.go").write_text("package executor\n")
    (root / "giga/deps/dep.go").write_text("package deps\n")
    (root / "autobahn/consensus/cons.go").write_text("package consensus\n")
    (root / "evmone/backend/be.go").write_text("package backend\n")
    (root / "x/evm/keeper/msg.go").write_text("package keeper\n")
    (root / "SCOPE.md").write_text(SEI_LIKE_SCOPE)


def _run(args):
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=REPO, capture_output=True, text=True, timeout=30,
    )


class DispatchGuardTests(unittest.TestCase):
    def test_oos_batch_blocked_rc1(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_ws(ws)
            batch = ws / "agent_batch.md"
            batch.write_text(
                "# hunt batch\n\n"
                "- `autobahn/consensus/cons.go` :: ProcessBlock\n"
                "- `x/evm/keeper/msg.go` :: MsgHandler\n"
            )
            r = _run(["--workspace", str(ws), "--batch", str(batch)])
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("OOS (blocked)", r.stdout)
            self.assertIn("autobahn", r.stderr)

    def test_all_in_scope_rc0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_ws(ws)
            batch = ws / "agent_batch.md"
            batch.write_text(
                "# hunt batch\n\n"
                "- `giga/executor/exec.go` :: Execute\n"
                "- `x/evm/keeper/msg.go` :: MsgHandler\n"
            )
            r = _run(["--workspace", str(ws), "--batch", str(batch)])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("pass-no-oos-in-batch", r.stdout)

    def test_giga_executor_never_blocked(self) -> None:
        # CRITICAL: the include-exception path must never be flagged OOS even
        # though **/giga/** is an exclude glob.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_ws(ws)
            batch = ws / "b.md"
            batch.write_text("- `giga/executor/exec.go` :: Execute\n")
            r = _run(["--workspace", str(ws), "--batch", str(batch)])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_allow_oos_warns_rc0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_ws(ws)
            batch = ws / "b.md"
            batch.write_text("- `evmone/backend/be.go` :: Run\n")
            r = _run(["--workspace", str(ws), "--batch", str(batch),
                      "--allow-oos"])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("ALLOWED", r.stdout)

    def test_override_marker_warns_rc0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_ws(ws)
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            (ws / ".auditooor" / "scope_oos_dispatch_override").write_text("ok\n")
            batch = ws / "b.md"
            batch.write_text("- `evmone/backend/be.go` :: Run\n")
            r = _run(["--workspace", str(ws), "--batch", str(batch)])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("ALLOWED", r.stdout)

    def test_no_oos_section_fail_open_rc0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_ws(ws)
            (ws / "SCOPE.md").write_text("# Scope\n\n## In scope\n\n- All.\n")
            batch = ws / "b.md"
            batch.write_text("- `autobahn/consensus/cons.go` :: X\n")
            r = _run(["--workspace", str(ws), "--batch", str(batch)])
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("pass-no-oos-in-batch", r.stdout)

    def test_bare_basename_resolved(self) -> None:
        # A bare basename in the batch should resolve against the tree.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_ws(ws)
            batch = ws / "b.md"
            batch.write_text("- cons.go :: ProcessBlock\n")
            r = _run(["--workspace", str(ws), "--batch", str(batch)])
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_jsonl_units_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _mk_ws(ws)
            uf = ws / "units.jsonl"
            uf.write_text(
                '{"file": "autobahn/consensus/cons.go", "function": "X"}\n'
                '{"file": "giga/executor/exec.go", "function": "Y"}\n'
            )
            r = _run(["--workspace", str(ws), "--units-file", str(uf)])
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("autobahn", r.stderr)


if __name__ == "__main__":
    unittest.main()
