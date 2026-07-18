#!/usr/bin/env python3
"""Tests for ``tools/go-unbounded-alloc-noprogress-screen.py`` (G9).

G9 is a GENERAL enforcement-completeness screen, NOT a bug shape: for every
length-sized-work primitive (eager allocation ``make``/``growslice``/``Grow`` OR
a length-bounded ``for`` loop) whose size is a decode/wire-boundary length, it
asks "does a MAX-cap enforcement point dominate the alloc/loop?" and emits an
advisory (verdict=needs-fuzz) row ONLY when no dominating cap exists.

Coverage
--------
 1. test_planted_positive_alloc_fires   - unbounded decode-length make([]byte,n) fires.
 2. test_planted_positive_loop_fires    - unbounded decode-length for-loop bound fires.
 3. test_guarded_alloc_silent           - same alloc + `if n > MAX { return }` stays silent.
 4. test_guarded_loop_silent            - same loop + cap guard stays silent.
 5. test_materialized_len_excluded      - make([]byte, len(x)) (materialized) never fires.
 6. test_const_len_excluded             - make([]byte, MAXLEN) (compile-time const) never fires.
 7. test_inline_wire_read_fires         - make([]byte, 0, int(binary.BigEndian.Uint32(b))) fires.
 8. test_make_cap_and_grow_primitives   - make cap arg, growslice, .Grow(n) all fire.
 9. test_test_file_excluded             - *_test.go patterns are ignored by enumeration.
10. test_advisory_first_default_exit_zero - default run NEVER fail-closes (exit 0 with rows).
11. test_strict_opt_in_exit_one         - `--strict` exits 1 when a row is present.
12. test_row_schema_advisory_fields     - row carries verdict=needs-fuzz, auto_credit=False, advisory=True.
13. test_sidecar_emitted                - <ws>/.auditooor/go_unbounded_alloc_noprogress_hypotheses.jsonl written.
14. test_non_vacuous_neutralize_source  - neutralizing the boundary-source predicate silences the positive.
15. test_non_vacuous_neutralize_cap     - neutralizing the cap predicate (always-capped) silences the positive.
16. test_real_fleet_mutation_verify     - SEI go-ethereum rlpx guarded=silent, guard-removed temp copy=fires.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "go-unbounded-alloc-noprogress-screen.py"

# Real fleet mutation-verify target (read-only): SEI go-ethereum rlpx Conn.Read
# reads the snappy DecodedLen and caps it (`if actualSize > maxUint24`) BEFORE
# growslice(...). Guarded original -> silent; guard removed on a temp copy -> fires.
SEI_RLPX = Path(os.path.expanduser(
    "~/audits/sei/src/go-ethereum/p2p/rlpx/rlpx.go"
))


def _load_module():
    spec = importlib.util.spec_from_file_location("g9ua_mod", SCANNER)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["g9ua_mod"] = mod  # register BEFORE exec (py3.14 dataclass resolution)
    spec.loader.exec_module(mod)
    return mod


def _run_cli(workspace: Path, extra: list[str] | None = None) -> tuple[dict, int]:
    cmd = [sys.executable, str(SCANNER), "--workspace", str(workspace), "--print-json"]
    if extra:
        cmd.extend(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode in (0, 1), proc.stdout + proc.stderr
    return json.loads(proc.stdout), proc.returncode


def _write(ws: Path, body: str, relpath: str = "src/decoder.go") -> Path:
    p = ws / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


# Planted POSITIVE (alloc): a decoder reads a length prefix and eagerly allocs,
# NO cap. The general shape G9 must fire on.
POSITIVE_ALLOC = """
    package p

    import "encoding/binary"

    func DecodeFrame(data []byte) []byte {
        n := binary.BigEndian.Uint32(data[0:4])
        out := make([]byte, n)
        return out
    }
"""

# Planted POSITIVE (loop): decode-boundary length bounds a for-loop, no cap.
POSITIVE_LOOP = """
    package p

    import "encoding/binary"

    func DecodeItems(data []byte) int {
        n := binary.BigEndian.Uint32(data[0:4])
        total := 0
        for i := uint32(0); i < n; i++ {
            total += int(data[i%4])
        }
        return total
    }
"""

# Guarded NEGATIVE (alloc): identical, but with a dominating MAX cap.
GUARDED_ALLOC = """
    package p

    import "encoding/binary"

    const MaxFrame = 16 * 1024 * 1024

    func DecodeFrame(data []byte) ([]byte, error) {
        n := binary.BigEndian.Uint32(data[0:4])
        if n > MaxFrame {
            return nil, errFrameTooLarge
        }
        out := make([]byte, n)
        return out, nil
    }
"""

# Guarded NEGATIVE (loop): identical loop but with a dominating cap guard.
GUARDED_LOOP = """
    package p

    import "encoding/binary"

    const MaxItems = 1024

    func DecodeItems(data []byte) (int, error) {
        n := binary.BigEndian.Uint32(data[0:4])
        if n > MaxItems {
            return 0, errTooMany
        }
        total := 0
        for i := uint32(0); i < n; i++ {
            total += int(data[i%4])
        }
        return total, nil
    }
"""


class TestG9UA(unittest.TestCase):
    def test_planted_positive_alloc_fires(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_ALLOC)
            payload, _ = _run_cli(ws)
            self.assertGreaterEqual(payload["row_count"], 1)
            self.assertTrue(any(r["kind"] == "alloc" for r in payload["rows"]))
            self.assertTrue(any(r["length_token"] == "n" for r in payload["rows"]))

    def test_planted_positive_loop_fires(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_LOOP)
            payload, _ = _run_cli(ws)
            self.assertTrue(
                any(r["kind"] == "loop" and r["primitive"] == "loop_bound"
                    for r in payload["rows"]),
                payload["rows"],
            )

    def test_guarded_alloc_silent(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, GUARDED_ALLOC)
            payload, _ = _run_cli(ws)
            self.assertFalse(
                any(r["length_token"] == "n" for r in payload["rows"]),
                payload["rows"],
            )

    def test_guarded_loop_silent(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, GUARDED_LOOP)
            payload, _ = _run_cli(ws)
            self.assertFalse(
                any(r["kind"] == "loop" for r in payload["rows"]),
                payload["rows"],
            )

    def test_materialized_len_excluded(self):
        body = """
        package p
        func Copy(src []byte) []byte {
            out := make([]byte, len(src))
            copy(out, src)
            return out
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_const_len_excluded(self):
        body = """
        package p
        const MAXLEN = 32
        func Fixed() []byte {
            return make([]byte, MAXLEN)
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_inline_wire_read_fires(self):
        # make([]byte, 0, int(binary.BigEndian.Uint32(b))) - inline wire read as
        # the capacity, no cap -> fires (inline_wire_read).
        body = """
        package p
        import "encoding/binary"
        func ReadReply(chunk []byte) []byte {
            reply := make([]byte, 0, int(binary.BigEndian.Uint32(chunk[5:9])))
            return reply
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertGreaterEqual(payload["row_count"], 1, payload["rows"])
            self.assertTrue(
                any(r["boundary_source"] == "inline_wire_read"
                    for r in payload["rows"]),
                payload["rows"],
            )

    def test_make_cap_and_grow_primitives(self):
        body = """
        package p
        import "encoding/binary"
        func A(data []byte) {
            n := binary.BigEndian.Uint32(data[0:4])
            _ = make([]byte, 0, n)
        }
        func B(data []byte) {
            sz := binary.BigEndian.Uint64(data[0:8])
            _ = growslice(base, sz)
        }
        func C(buf *bytes.Buffer, data []byte) {
            cnt := binary.BigEndian.Uint32(data[0:4])
            buf.Grow(int(cnt))
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            prims = {r["primitive"] for r in payload["rows"]}
            self.assertIn("make_cap", prims)
            self.assertIn("growslice", prims)
            self.assertIn("grow", prims)

    def test_test_file_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_ALLOC, relpath="src/decoder_test.go")
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_write_helper_no_byte_param_silent(self):
        # Fleet FP (go-ethereum rlpx writeBuffer.appendZero): an internal
        # zero-fill WRITE helper `func (b *writeBuffer) appendZero(n int)` whose
        # body mentions `b.data` and `[]byte` (inside the very make) must NOT be
        # treated as a decode context - `n` is caller-supplied, not wire-derived.
        body = """
        package p
        func (b *writeBuffer) appendZero(n int) []byte {
            offset := len(b.data)
            b.data = append(b.data, make([]byte, n)...)
            return b.data[offset : offset+n]
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_byte_param_decode_ctx_still_fires(self):
        # Non-vacuity of the tightened predicate: a fn that DOES take a []byte
        # wire param and sizes a make by a length-named param still fires.
        mod = _load_module()
        self.assertTrue(mod.is_decode_context("parseThing", "data []byte, n int", ""))
        self.assertTrue(mod.is_decode_context("f", "r io.Reader, size int", ""))
        # ...but a scalar-only param list with a body []byte mention does NOT.
        self.assertFalse(mod.is_decode_context("appendZero", "n int", "make([]byte, n)"))

    def test_advisory_first_default_exit_zero(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_ALLOC)
            _payload, rc = _run_cli(ws)  # no --strict
            self.assertEqual(rc, 0)

    def test_strict_opt_in_exit_one(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_ALLOC)
            _payload, rc = _run_cli(ws, ["--strict"])
            self.assertEqual(rc, 1)

    def test_row_schema_advisory_fields(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_ALLOC)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["verdict_all"], "needs-fuzz")
            self.assertTrue(payload["advisory_first"])
            row = payload["rows"][0]
            for f in ("file", "line", "primitive", "kind", "function",
                      "length_expr", "length_token", "boundary_source",
                      "invariant", "detector", "attack_class", "hacker_question",
                      "verdict", "auto_credit", "advisory"):
                self.assertIn(f, row)
            self.assertEqual(row["verdict"], "needs-fuzz")
            self.assertFalse(row["auto_credit"])
            self.assertTrue(row["advisory"])

    def test_sidecar_emitted(self):
        # The default (non print-json) run writes the foldable JSONL sidecar.
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_ALLOC)
            proc = subprocess.run(
                [sys.executable, str(SCANNER), "--workspace", str(ws)],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            sidecar = ws / ".auditooor" / "go_unbounded_alloc_noprogress_hypotheses.jsonl"
            self.assertTrue(sidecar.is_file(), "sidecar not written")
            lines = [ln for ln in sidecar.read_text().splitlines() if ln.strip()]
            self.assertGreaterEqual(len(lines), 1)
            rec = json.loads(lines[0])
            self.assertEqual(rec["capability"], "G9")
            self.assertEqual(rec["verdict"], "needs-fuzz")
            self.assertFalse(rec["auto_credit"])
            self.assertTrue(rec["advisory"])

    # -- Non-vacuity: neutralizing either half of the core predicate must make
    #    the planted positive disappear. -----------------------------------

    def test_non_vacuous_neutralize_source(self):
        mod = _load_module()
        rel = "src/decoder.go"
        text = textwrap.dedent(POSITIVE_ALLOC)
        self.assertGreaterEqual(len(mod.scan_text(text, rel)), 1)  # baseline fires
        orig = mod.classify_boundary_source
        try:
            mod.classify_boundary_source = lambda *a, **k: (None, "")
            self.assertEqual(mod.scan_text(text, rel), [])  # positive silenced
        finally:
            mod.classify_boundary_source = orig
        self.assertGreaterEqual(len(mod.scan_text(text, rel)), 1)  # restored

    def test_non_vacuous_neutralize_cap(self):
        mod = _load_module()
        rel = "src/decoder.go"
        text = textwrap.dedent(POSITIVE_ALLOC)
        self.assertGreaterEqual(len(mod.scan_text(text, rel)), 1)  # baseline fires
        orig = mod.has_dominating_cap
        try:
            mod.has_dominating_cap = lambda *a, **k: (True, "neutralized")
            self.assertEqual(mod.scan_text(text, rel), [])  # positive silenced
        finally:
            mod.has_dominating_cap = orig
        self.assertGreaterEqual(len(mod.scan_text(text, rel)), 1)  # restored

    @unittest.skipUnless(SEI_RLPX.is_file(), "SEI fleet snapshot absent")
    def test_real_fleet_mutation_verify(self):
        mod = _load_module()
        original = SEI_RLPX.read_text(encoding="utf-8")

        # Guarded original: the growslice(c.snappyReadBuffer, actualSize) is
        # dominated by `if actualSize > maxUint24 { return ... }` -> SILENT for
        # the actualSize-sized reservation.
        rows_guarded = mod.scan_text(original, "rlpx.go")
        self.assertFalse(
            any(r.length_token == "actualSize" for r in rows_guarded),
            f"expected silent on guarded actualSize alloc, got "
            f"{[r.length_token for r in rows_guarded]}",
        )

        # Mutant (temp copy, cap guard weakened): must FIRE. Never mutate the ws file.
        mutant = re.sub(
            r"if actualSize > maxUint24 \{\s*"
            r"return code, nil, 0, errPlainMessageTooLarge\s*\}",
            "// cap guard removed by mutation-verify",
            original,
        )
        self.assertNotEqual(mutant, original, "mutation regex failed to apply")
        rows_mutant = mod.scan_text(mutant, "rlpx.go")
        self.assertTrue(
            any(r.length_token == "actualSize" for r in rows_mutant),
            "expected fire when cap guard removed",
        )


if __name__ == "__main__":
    unittest.main()
