#!/usr/bin/env python3
"""Tests for tools/go-mpc-coordination.py - the Go-side threshold-sig
coordination reasoner. >=2 per arm, each arm carries a NON-VACUOUS mutation pair
(add the required coupled action -> the survivor disappears / becomes KEPT).

The fixtures are tiny synthetic Go packages so the set-difference is exercised
end-to-end (parse -> callgraph closure -> ACT gate -> required set-difference).
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "go-mpc-coordination.py"

_spec = importlib.util.spec_from_file_location("go_mpc_coordination", _TOOL)
mpc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mpc)


def _write_pkg(root: Path, name: str, body: str):
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.go").write_text(body, encoding="utf-8")


def _run(src_root: Path, ws: Path) -> dict:
    argv = ["--workspace", str(ws), "--src-root", str(src_root), "--json"]
    # capture the returned summary directly
    return mpc.run(argv)


class ArmABase(unittest.TestCase):
    """ARM A - rotation-without-resharing."""

    def _mk(self, tmp: Path, with_reshare: bool):
        # Keeper.RotateKey writes the active key (act gate: setKey) and, in the
        # mutation, ALSO triggers a keygen for the new set.
        reshare = "k.createKeygenSession(ctx, id)" if with_reshare else "// no reshare"
        body = f"""
package keeper
func (k Keeper) setKey(ctx C, key K) {{ k.store.Set(key) }}
func (k Keeper) getKeyEpoch(ctx C, n int) (E, bool) {{ return E{{}}, true }}
func (k Keeper) createKeygenSession(ctx C, id ID) error {{ return nil }}
func (k Keeper) RotateKey(ctx C, chain string) error {{
    epoch, _ := k.getKeyEpoch(ctx, 1)
    k.setKey(ctx, epoch.Key)
    {reshare}
    return nil
}}
"""
        _write_pkg(tmp, "keeper", body)

    def test_survivor_when_no_reshare(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._mk(tmp, with_reshare=False)
            s = _run(tmp, tmp)
            arm = s["arms"]["A_rotation_without_resharing"]
            self.assertEqual(arm["survivor_count"], 1, s)
            self.assertTrue(any(x["fn"] == "rotatekey" for x in arm["survivors"]))
            self.assertEqual(s["substrate_status"], "survivors_found")

    def test_mutation_kills_survivor(self):
        # NON-VACUOUS: adding the resharing trigger removes the survivor.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._mk(tmp, with_reshare=True)
            s = _run(tmp, tmp)
            arm = s["arms"]["A_rotation_without_resharing"]
            self.assertEqual(arm["survivor_count"], 0, s)
            self.assertTrue(any(x["fn"] == "rotatekey" for x in arm["KEPT"]), s)


class ArmBBase(unittest.TestCase):
    """ARM B - threshold-against-active-set-only."""

    def _mk(self, tmp: Path, with_produced_binding: bool):
        # SubmitSignature reaches a threshold check (act gate). In the mutation it
        # also binds to the produced set (getSigningSession -> snapshot).
        bind = "sess := k.getSigningSession(ctx, id)\n    _ = sess" \
            if with_produced_binding else "// no produced-set binding"
        body = f"""
package keeper
func (k Keeper) getSigningSession(ctx C, id ID) S {{ return S{{}} }}
func (k Keeper) meetsThreshold(w int) bool {{ return true }}
func (k Keeper) SubmitSignature(ctx C, id ID) error {{
    {bind}
    if k.meetsThreshold(currentActiveWeight()) {{ return nil }}
    return nil
}}
"""
        _write_pkg(tmp, "keeper", body)

    def test_survivor_when_active_set_only(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._mk(tmp, with_produced_binding=False)
            s = _run(tmp, tmp)
            arm = s["arms"]["B_threshold_against_active_set_only"]
            self.assertEqual(arm["survivor_count"], 1, s)
            self.assertTrue(any(x["fn"] == "submitsignature"
                                for x in arm["survivors"]))

    def test_mutation_kills_survivor(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._mk(tmp, with_produced_binding=True)
            s = _run(tmp, tmp)
            arm = s["arms"]["B_threshold_against_active_set_only"]
            self.assertEqual(arm["survivor_count"], 0, s)
            self.assertTrue(any(x["fn"] == "submitsignature"
                                for x in arm["KEPT"]), s)


class ArmCBase(unittest.TestCase):
    """ARM C - nonce/session reuse."""

    def _mk(self, tmp: Path, with_freshness: bool):
        # createSigningSession stores a session (act gate: setSigningSession). In
        # the mutation it first checks the id is not already in use (freshness).
        fresh = "if _, ok := k.getSigningSession(ctx, id); ok { return errDup }" \
            if with_freshness else "// no freshness guard"
        body = f"""
package keeper
func (k Keeper) getSigningSession(ctx C, id ID) (S, bool) {{ return S{{}}, false }}
func (k Keeper) setSigningSession(ctx C, s S) {{ k.store.Set(s) }}
func (k Keeper) createSigningSession(ctx C, id ID) error {{
    {fresh}
    k.setSigningSession(ctx, newSession(id))
    return nil
}}
"""
        _write_pkg(tmp, "keeper", body)

    def test_survivor_when_no_freshness(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._mk(tmp, with_freshness=False)
            s = _run(tmp, tmp)
            arm = s["arms"]["C_nonce_session_reuse"]
            self.assertEqual(arm["survivor_count"], 1, s)
            self.assertTrue(any(x["fn"] == "createsigningsession"
                                for x in arm["survivors"]))

    def test_mutation_kills_survivor(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self._mk(tmp, with_freshness=True)
            s = _run(tmp, tmp)
            arm = s["arms"]["C_nonce_session_reuse"]
            self.assertEqual(arm["survivor_count"], 0, s)
            self.assertTrue(any(x["fn"] == "createsigningsession"
                                for x in arm["KEPT"]), s)


class HonestyTests(unittest.TestCase):
    def test_substrate_vacuous_no_go(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "readme.md").write_text("no go here", encoding="utf-8")
            s = _run(tmp, tmp)
            self.assertEqual(s["substrate_status"], "substrate_vacuous")
            self.assertTrue(s["advisory"])

    def test_cited_empty_when_all_kept(self):
        # coordination entrypoints exist and every one is correctly coupled ->
        # honest clean 0 (cited_empty), NOT vacuous.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            body = """
package keeper
func (k Keeper) getKeygenSession(ctx C, id ID) (S, bool) { return S{}, false }
func (k Keeper) createKeygenSession(ctx C, id ID) error {
    if _, ok := k.getKeygenSession(ctx, id); ok { return errDup }
    return nil
}
func (k Keeper) getKeyEpoch(ctx C, n int) (E, bool) { return E{}, true }
func (k Keeper) setKey(ctx C, key K) { k.store.Set(key) }
func (k Keeper) RotateKey(ctx C, chain string) error {
    epoch, _ := k.getKeyEpoch(ctx, 1)
    k.setKey(ctx, epoch.Key)
    k.createKeygenSession(ctx, epoch.ID)
    return nil
}
"""
            _write_pkg(tmp, "keeper", body)
            s = _run(tmp, tmp)
            self.assertEqual(s["substrate_status"], "cited_empty", s)
            self.assertEqual(s["total_survivors"], 0)

    def test_advisory_needs_source_on_obligations(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            body = """
package keeper
func (k Keeper) setKey(ctx C, key K) { k.store.Set(key) }
func (k Keeper) getKeyEpoch(ctx C, n int) (E, bool) { return E{}, true }
func (k Keeper) RotateKey(ctx C, chain string) error {
    epoch, _ := k.getKeyEpoch(ctx, 1)
    k.setKey(ctx, epoch.Key)
    return nil
}
"""
            _write_pkg(tmp, "keeper", body)
            emit = tmp / "out.jsonl"
            s = mpc.run(["--workspace", str(tmp), "--src-root", str(tmp),
                         "--emit", str(emit), "--json"])
            rows = [json.loads(l) for l in emit.read_text().splitlines() if l.strip()]
            self.assertTrue(rows)
            for r in rows:
                self.assertEqual(r["schema"], "auditooor.go_mpc_coordination.v1")
                self.assertEqual(r["quality_gate_status"], "needs_source")
                self.assertTrue(r["advisory_only"])
                self.assertTrue(r["source_refs"])

    def test_fail_closed_exits_nonzero_on_vacuous(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "x.txt").write_text("nope", encoding="utf-8")
            r = subprocess.run(
                [sys.executable, str(_TOOL), "--workspace", str(tmp),
                 "--src-root", str(tmp), "--fail-closed"],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 3, r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
