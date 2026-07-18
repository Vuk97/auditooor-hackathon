#!/usr/bin/env python3
"""Guard: the `make dataflow-slice` OUTER wrapper timeout must EXCEED
go-dataflow.py's INTERNAL run-timeout ceiling, or a heavy Go monorepo gets its
LoadAllSyntax+SSA slice killed by the wrapper before the tool finishes, silently
truncating to 0 paths -> fail-dataflow-substrate-starved.

Root cause (axelar-dlt 2026-07-13): the Makefile wrapper defaulted
AUDITOOOR_DATAFLOW_TIMEOUT to 1800s while go-dataflow.py's own
AUDITOOOR_GO_DATAFLOW_RUN_TIMEOUT default is 3600s (a cosmos-sdk full closure is
genuinely ~42min, NOT a hang). The 1800s wrapper strangled it at 30min.
"""
import re
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]
_REPO = Path(__file__).resolve().parents[2]


def _wrapper_default() -> int:
    mk = (_REPO / "Makefile").read_text(encoding="utf-8")
    m = re.search(r"AUDITOOOR_DATAFLOW_TIMEOUT:-(\d+)", mk)
    assert m, "dataflow-slice wrapper timeout default not found in Makefile"
    return int(m.group(1))


def _tool_default() -> int:
    src = (_TOOLS / "go-dataflow.py").read_text(encoding="utf-8")
    m = re.search(r'AUDITOOOR_GO_DATAFLOW_RUN_TIMEOUT",\s*"(\d+)"', src)
    assert m, "go-dataflow internal run-timeout default not found"
    return int(m.group(1))


class TestDataflowTimeoutWrapperExceedsTool(unittest.TestCase):
    def test_wrapper_exceeds_internal_ceiling(self):
        wrapper = _wrapper_default()
        tool = _tool_default()
        self.assertGreater(
            wrapper, tool,
            f"make dataflow-slice wrapper timeout ({wrapper}s) must exceed "
            f"go-dataflow.py internal ceiling ({tool}s) or heavy Go slices are "
            f"truncated to 0 paths (fail-dataflow-substrate-starved)")

    def test_headroom_at_least_10pct(self):
        # a hard-truncation right at the ceiling still races the router's other
        # arms + process teardown; require modest headroom.
        self.assertGreaterEqual(_wrapper_default(), int(_tool_default() * 1.1))


if __name__ == "__main__":
    unittest.main()
