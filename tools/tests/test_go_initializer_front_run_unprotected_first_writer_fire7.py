from __future__ import annotations

import importlib.util
import json
import py_compile
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent.parent
TOOL_PATH = (
    REPO_ROOT
    / "tools"
    / "detectors"
    / "go_ast_initializer_front_run_unprotected_first_writer.py"
)
FIXTURE_DIR = ROOT / "fixtures" / "go-detector-runner"
POSITIVE = FIXTURE_DIR / "positive" / "initializer_front_run_unprotected_first_writer_fire7.go"
NEGATIVE = FIXTURE_DIR / "negative" / "initializer_front_run_unprotected_first_writer_fire7_guarded.go"


def _load_detector():
    spec = importlib.util.spec_from_file_location(
        "go_ast_initializer_front_run_unprotected_first_writer",
        TOOL_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load detector")
    module = importlib.util.module_from_spec(spec)
    sys.modules["go_ast_initializer_front_run_unprotected_first_writer"] = module
    spec.loader.exec_module(module)
    return module


detector = _load_detector()


def _run(root: Path) -> dict:
    buf = StringIO()
    with redirect_stdout(buf):
        rc = detector.main([str(root)])
    payload = json.loads(buf.getvalue())
    payload["_rc"] = rc
    return payload


class GoInitializerFrontRunUnprotectedFirstWriterFire7Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(TOOL_PATH), doraise=True)

    def test_positive_fixture_fires_on_unprotected_first_writer_paths(self) -> None:
        payload = _run(POSITIVE)
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(
            payload["schema"],
            "auditooor.go_initializer_front_run_unprotected_first_writer.v1",
        )
        self.assertEqual(payload["count"], 2, payload)
        functions = {candidate["function"] for candidate in payload["candidates"]}
        self.assertEqual(functions, {"Initialize", "RegisterRoute"})
        reasons = "\n".join(candidate["reason"] for candidate in payload["candidates"])
        self.assertIn("no deployer, factory, signer, or governance binding", reasons)
        snippets = "\n".join(candidate["snippet"] for candidate in payload["candidates"])
        self.assertIn("k.state.Boss = req.Boss", snippets)
        self.assertIn("k.state.Gateways[req.RemoteChainID] = req.RemoteGateway", snippets)

    def test_negative_fixture_is_silent_when_first_writer_is_caller_bound(self) -> None:
        payload = _run(NEGATIVE)
        self.assertEqual(payload["_rc"], 0)
        self.assertEqual(payload["count"], 0, payload)
        self.assertEqual(payload["candidates"], [])

    def test_fixture_shape_locks_source_backed_lift(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn('if k.state.Boss != ""', positive)
        self.assertIn("k.state.Boss = req.Boss", positive)
        self.assertIn("k.state.Gateways[req.RemoteChainID] = req.RemoteGateway", positive)
        self.assertNotIn("caller != k.deployer", positive)
        self.assertIn("caller != k.deployer", negative)
        self.assertIn("sender != k.factory", negative)


if __name__ == "__main__":
    unittest.main()
