"""Unit tests for Rule 20 no-fault-injection preflight."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "no_fault_injection_check",
    ROOT / "tools" / "no-fault-injection-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="r20_fault_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests").mkdir()
    return root


def _draft(severity: str = "HIGH", body: str = "", poc_ref: str = "") -> str:
    return f"Severity: {severity}\n\nSelected impact: Network-level downtime.\n\n{poc_ref}\n\n{body}\n"


def _write_case(body: str, source: str | None = None) -> Path:
    root = _workspace()
    if source is not None:
        d = root / "poc-tests" / "case"
        d.mkdir(parents=True)
        (d / "poc_test.go").write_text(source, encoding="utf-8")
        body += "\nPoC: `poc-tests/case`\n"
    draft = root / "submissions" / "paste_ready" / "draft-HIGH.md"
    draft.write_text(body, encoding="utf-8")
    return draft


class NoFaultInjectionTests(unittest.TestCase):
    def test_medium_severity_out_of_scope(self) -> None:
        draft = _write_case(_draft(severity="MEDIUM", body="faultyDB used here"))
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_high_faultydb_fails(self) -> None:
        draft = _write_case(_draft(body="The PoC arms faultyDB and forceFail."))
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-fault-injection")

    def test_fault_in_poc_dir_fails(self) -> None:
        draft = _write_case(
            _draft(),
            "package poc\nfunc TestX(t *testing.T){ armFail.Store(true) }\n",
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["evidence"]["actionable_fault_hits"][0]["token"].lower(), "armfail")

    def test_latency_wrapper_with_safety_phrase_passes(self) -> None:
        draft = _write_case(
            _draft(body="slowBatchDB is hardware-latency modeling, not fault injection.")
        )
        rc, payload = mod.run(draft)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-fault-injection")

    def test_safety_phrase_passes_nonstrict(self) -> None:
        draft = _write_case(_draft(body="faultyBatch was used, but wrapper stripped for the final unmodified runtime PoC."))
        rc, payload = mod.run(draft, strict=False)
        self.assertEqual(rc, 0)
        self.assertIn(payload["verdict"], {"pass-no-fault-injection", "pass-safety-disclosure"})

    def test_strict_ignores_safety_phrase(self) -> None:
        draft = _write_case(_draft(body="faultyBatch is present. No fault injection in the production proof."))
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-fault-injection")

    def test_removed_line_passes(self) -> None:
        draft = _write_case(_draft(body="The old ~~faultyDB~~ wrapper was removed before final proof."))
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-no-fault-injection")

    def test_rebuttal_passes(self) -> None:
        draft = _write_case(_draft(body="faultyDB token in prior quote. <!-- r20-rebuttal: quoted triager text only -->"))
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_missing_file_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/file.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
