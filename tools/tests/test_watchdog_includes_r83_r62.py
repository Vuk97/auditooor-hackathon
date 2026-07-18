"""Regression: the write-time pre-submit-watchdog (run by the Claude PostToolUse
hook submission-markdown-posttooluse.sh on every submissions/**/*.md write) MUST
include the R83 hardening-vs-vulnerability gate and the R62 triager-mindset
simulator, and they must fire on a Zebra-shaped hardening draft at write-time.
Anchor: closing the gap where R83/R62 only ran at promotion, not at draft-write.
"""
import importlib.util, json, sys, tempfile, unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "pre-submit-watchdog.py"


def _load():
    spec = importlib.util.spec_from_file_location("psw", _T)
    m = importlib.util.module_from_spec(spec)
    sys.modules["psw"] = m
    spec.loader.exec_module(m)
    return m


PSW = _load()

ZEBRA = """# Mempool per-peer download cap keyed on full SocketAddr
- Severity: HIGH
## Impact
A single unauthenticated source IP obtains 5*N in-flight download slots over N
connections, saturating the global mempool download queue, denying honest peers.
## PoC
A Downloads-level unit test constructs same-IP SocketAddrs directly; on default
config max_connections_per_ip is 1 so the connection layer already enforces the bound.
"""


class TestWatchdogIncludesR83R62(unittest.TestCase):
    def test_quick_gates_include_r83_and_r62(self):
        cmds = PSW.quick_gate_commands(Path("/x/d.md"), Path("/x"), "HIGH")
        names = [c[0] for c in cmds]
        self.assertIn("R83-HARDENING-VS-VULN", names)
        self.assertIn("R62-TRIAGER-MINDSET", names)

    def test_r62_argv_has_no_invalid_json_flag(self):
        cmds = PSW.quick_gate_commands(Path("/x/d.md"), Path("/x"), None)
        r62 = next(c for c in cmds if c[0] == "R62-TRIAGER-MINDSET")
        self.assertNotIn("--json", r62[1])  # simulator has no --json flag

    def test_r83_fires_on_zebra_hardening_draft_at_writetime(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            d = ws / "submissions" / "staging" / "z" / "z.md"
            d.parent.mkdir(parents=True)
            d.write_text(ZEBRA, encoding="utf-8")
            res = PSW.run_quick(d, ws)
            gates = {g["gate"]: g for g in res.get("gates", res.get("failures", []))}
            # run_quick returns a structure; pull the R83 result whichever shape
            allg = res.get("gates") or []
            r83 = next((g for g in allg if g["gate"] == "R83-HARDENING-VS-VULN"), None)
            self.assertIsNotNone(r83, f"R83 not run; keys={list(res.keys())}")
            self.assertTrue(r83["failed"], r83.get("summary"))
            self.assertIn("default-defense", str(r83.get("summary", "")).lower() + str(r83.get("payload", "")).lower())


if __name__ == "__main__":
    unittest.main()
