"""Regression: a go-dataflow module carrying a STALE degrade record (a later timed-out
re-run) alongside thousands of REAL analyzed paths in the SAME dataflow_paths.jsonl is
genuinely covered - the degrade must not false-RED state-coupling. Root-caused 2026-07-14
(axelar src/axelar-core: 4154 real records vs 3 degrade records)."""
import importlib.util, json, pathlib, sys, tempfile, unittest

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "audit-completeness-check.py"
_spec = importlib.util.spec_from_file_location("_acc_scd", _TOOL)
_M = importlib.util.module_from_spec(_spec); sys.modules["_acc_scd"] = _M
_spec.loader.exec_module(_M)


class TestSupersededDegrade(unittest.TestCase):
    def _ws(self, records):
        d = pathlib.Path(tempfile.mkdtemp()); (d / ".auditooor").mkdir()
        (d / ".auditooor" / "dataflow_paths.jsonl").write_text(
            "\n".join(json.dumps(r) for r in records))
        return d

    def test_module_with_real_paths_is_covered(self):
        d = self._ws([{"module": "/x/src/axelar-core", "source": {"file": "src/axelar-core/x.go"}},
                      {"degraded": True, "module": "/x/src/axelar-core"}])
        cov = _M._modules_with_real_dataflow_paths(d)
        self.assertTrue(_M._module_is_covered("src/axelar-core", cov))

    def test_module_with_only_degrade_not_covered(self):
        d = self._ws([{"degraded": True, "module": "/x/src/axelar-core"}])
        cov = _M._modules_with_real_dataflow_paths(d)
        self.assertFalse(_M._module_is_covered("src/axelar-core", cov))

    def test_no_loose_substring_match(self):
        d = self._ws([{"module": "/x/src/axelar-core-utils", "source": {"file": "src/axelar-core-utils/y.go"}}])
        cov = _M._modules_with_real_dataflow_paths(d)
        # a DIFFERENT module (src/axelar) must not be credited by substring
        self.assertFalse(_M._module_is_covered("src/other", cov))


if __name__ == "__main__":
    unittest.main()
