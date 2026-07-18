"""Guard: the Oscript AA enumerator (tools/oscript-aa-enumerate.py) enumerates
Obyte Autonomous-Agent units from real-shaped .oscript/.aa sources so
`.auditooor/inscope_units.jsonl` includes them (was Solidity-only: the Obyte
engagement had 410 .sol units and ZERO of its ~40 in-scope .oscript/.aa AA
files enumerated).

Covers:
  * a bare-object AA (init + messages.cases[2] + getters with 2 $fns) -> the
    expected 2 message-case + 2 getter + 1 init units, all lang="oscript";
  * a plain-array `messages:[...]` AA -> a single message-handler unit;
  * the ['autonomous agent', {...}] wrapper form AND a double-quoted formula
    (`init: "{ ... bounce("x") ... }"`) with nested unescaped quotes (tolerance
    against the delimiter that broke a naive quote-scanner on export.oscript);
  * that tools/scope_authority.py load_inscope can read the emitted rows;
  * that inserting one extra case grows the unit count by exactly 1 (real
    structural parsing, not a hardcoded count).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "oscript-aa-enumerate.py"
SCOPE_AUTH_PATH = REPO_ROOT / "tools" / "scope_authority.py"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


OSC = _load_module("oscript_aa_enumerate_test", MODULE_PATH)
SA = _load_module("scope_authority_osc_test", SCOPE_AUTH_PATH)


# A bare-object AA: init (backtick) + getters (1 const + 1 lambda) +
# messages.cases[2]. The first case moves value via payment + state.
FIXTURE_BARE = """{
    doc_url: "https://example.org/aa.json",
    init: `{
        $x = trigger.data.amount;
        if (!$x)
            bounce("no amount");
    }`,
    getters: `{
        $fee = 0.003;                       // a top-level constant getter
        $get_price = ($s) => $s * (1 + $fee);
    }`,
    messages: {
        cases: [
            { // deposit
                if: `{ trigger.data.deposit AND $x }`,
                messages: [
                    {
                        app: 'payment',
                        payload: { outputs: [{address: "{trigger.address}", amount: "{$x}"}] }
                    },
                    {
                        app: 'state',
                        state: `{ var['bal_' || trigger.address] += $x; }`
                    }
                ]
            },
            { // withdraw
                if: `{ trigger.data.withdraw }`,
                messages: [
                    {
                        app: 'state',
                        state: `{ var['bal_' || trigger.address] -= trigger.data.amount; }`
                    }
                ]
            }
        ]
    }
}
"""

# A plain-array `messages:[...]` AA: one always-run handler, plus 1 getter.
FIXTURE_ARRAY = """{
    getters: `{
        $lib_const = 42;
    }`,
    messages: [
        {
            app: 'state',
            state: `{ var['called'] = 1; }`
        }
    ]
}
"""

# Labelled ['autonomous agent', {...}] wrapper with a DOUBLE-QUOTED formula that
# itself contains nested unescaped double quotes (the export.oscript shape).
FIXTURE_LABELLED = """['autonomous agent', {
    init: "{ $y = 1; if (!$y) bounce("nope: " || $y); }",
    messages: {
        cases: [
            {
                if: "{ trigger.data.go }",
                messages: [ { app: 'payment', payload: {} } ]
            }
        ]
    }
}]
"""


def _kinds(rows):
    out = {}
    for r in rows:
        out[r["kind"]] = out.get(r["kind"], 0) + 1
    return out


class TestOscriptEnumerate(unittest.TestCase):
    def _write(self, ws, rel, content):
        p = ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_bare_object_units(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            p = self._write(ws, "src/example/agent.oscript", FIXTURE_BARE)
            rows = OSC.enumerate_file(p, ws)
            kinds = _kinds(rows)
            self.assertEqual(kinds.get("message-case"), 2, kinds)
            self.assertEqual(kinds.get("getter"), 2, kinds)
            self.assertEqual(kinds.get("init"), 1, kinds)
            self.assertEqual(len(rows), 5, rows)
            # every row is lang=oscript with a ws-relative posix file path
            for r in rows:
                self.assertEqual(r["lang"], "oscript")
                self.assertEqual(r["file"], "src/example/agent.oscript")
                self.assertIn("file_line", r)
            # getter names captured (const + lambda)
            getters = {r["fn"] for r in rows if r["kind"] == "getter"}
            self.assertEqual(getters, {"$fee", "$get_price"}, getters)
            # value-movers: the deposit case moves payment + state
            dep = next(r for r in rows if r["kind"] == "message-case"
                       and r["fn"] == "case_0")
            self.assertIn("payment", dep["value_movers"])
            self.assertIn("state", dep["value_movers"])

    def test_plain_array_messages_handler(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            p = self._write(ws, "src/lib/handler.aa", FIXTURE_ARRAY)
            rows = OSC.enumerate_file(p, ws)
            kinds = _kinds(rows)
            self.assertEqual(kinds.get("message-handler"), 1, kinds)
            self.assertEqual(kinds.get("getter"), 1, kinds)
            handler = next(r for r in rows if r["kind"] == "message-handler")
            self.assertEqual(handler["fn"], "messages")
            self.assertIn("state", handler["value_movers"])

    def test_labelled_wrapper_and_double_quoted_formula(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            p = self._write(ws, "src/wrap/aa.oscript", FIXTURE_LABELLED)
            rows = OSC.enumerate_file(p, ws)
            kinds = _kinds(rows)
            # the ['autonomous agent', {...}] wrapper is unwrapped; the
            # double-quoted init with nested quotes is recognised as non-trivial.
            self.assertEqual(kinds.get("message-case"), 1, kinds)
            self.assertEqual(kinds.get("init"), 1, kinds)

    def test_scope_authority_can_load_emitted_rows(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            self._write(ws, "src/example/agent.oscript", FIXTURE_BARE)
            self._write(ws, "src/lib/handler.aa", FIXTURE_ARRAY)
            # test/mock files MUST be skipped by the walker
            self._write(ws, "src/example/test/probe.oscript", FIXTURE_ARRAY)
            self._write(ws, "src/example/old-mock.oscript", FIXTURE_ARRAY)
            rows = OSC.enumerate_workspace(ws)
            files = {r["file"] for r in rows}
            self.assertIn("src/example/agent.oscript", files)
            self.assertIn("src/lib/handler.aa", files)
            self.assertNotIn("src/example/test/probe.oscript", files)
            self.assertNotIn("src/example/old-mock.oscript", files)
            # write the manifest and load it through scope_authority
            man = ws / ".auditooor" / "inscope_units.jsonl"
            man.parent.mkdir(parents=True, exist_ok=True)
            man.write_text(
                "".join(json.dumps(r, separators=(", ", ": ")) + "\n"
                        for r in rows), encoding="utf-8")
            SA.clear_cache()
            ins = SA.load_inscope(ws)
            self.assertTrue(ins.present)
            self.assertTrue(SA.is_inscope_file(ws, "src/example/agent.oscript"))
            self.assertTrue(
                SA.is_inscope_unit(ws, "src/example/agent.oscript", "case_0"))
            self.assertTrue(
                SA.is_inscope_unit(ws, "src/lib/handler.aa", "$lib_const"))

    def test_inserting_a_case_grows_count_by_one(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            p = self._write(ws, "src/example/agent.oscript", FIXTURE_BARE)
            before = len(OSC.enumerate_file(p, ws))
            extra = (
                "{ // inserted\n"
                "                if: `{ trigger.data.probe }`,\n"
                "                messages: [ { app: 'state', "
                "state: `{ var['p'] = 1; }` } ]\n"
                "            },\n            "
            )
            text = FIXTURE_BARE
            idx = text.index("cases: [") + len("cases: [")
            mutated = text[:idx] + "\n            " + extra + text[idx:]
            p.write_text(mutated, encoding="utf-8")
            after = len(OSC.enumerate_file(p, ws))
            self.assertEqual(after - before, 1, (before, after))


if __name__ == "__main__":
    unittest.main()
