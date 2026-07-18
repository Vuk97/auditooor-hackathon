#!/usr/bin/env python3
# <!-- r36-rebuttal: lane-eha-dep-exclude registered via agent-pathspec-register.py -->
"""Guard: the engine-harness-author contract selection (audit-deep-solidity)
excludes vendored dependency / build dirs so `sort | head -N` is not consumed by
forge-std and the real in-scope contracts are authored.

Replicates the Makefile find used to feed evm-engine-harness-author and asserts
lib/node_modules/out/cache/script/forge-std are filtered. Regression guard for
the beanstalk mixed-layout hollow-engine root cause (R91): lib/forge-std/src/*.sol
sorted ahead of src/<real>.sol and ate the whole HARNESS_AUTHOR_MAX_CONTRACTS cap.
"""
import subprocess
import tempfile
import unittest
from pathlib import Path

# The exact exclude set the Makefile applies (kept in sync with audit-deep-solidity).
_EXCLUDES = [
    "*/test/*", "*/tests/*", "*/mock*", "*/Mock*", "*/interfaces/*",
    "*/interface/*", "*/.git/*", "*/lib/*", "*/node_modules/*", "*/out/*",
    "*/cache/*", "*/script/*", "*/forge-std/*", "*/.auditooor/*",
]


def _author_find(ws: Path, cap: int) -> list[str]:
    args = ["find", str(ws / "src"), "-type", "f", "-name", "*.sol"]
    for ex in _EXCLUDES:
        args += ["!", "-path", ex]
    args += ["-print"]
    out = subprocess.run(args, capture_output=True, text=True).stdout
    rels = sorted(line.replace(str(ws) + "/", "") for line in out.splitlines() if line.strip())
    return rels[:cap]


class TestEhaDepExclude(unittest.TestCase):
    def _mkws(self) -> Path:
        ws = Path(tempfile.mkdtemp())
        files = [
            # vendored deps that MUST be excluded (sort ahead of real src)
            "src/basin/lib/forge-std/src/Base.sol",
            "src/basin/lib/forge-std/src/StdJson.sol",
            "src/basin/node_modules/@oz/Ownable.sol",
            "src/basin/out/Well.sol",
            "src/basin/cache/x.sol",
            "src/pipeline/script/Deploy.s.sol",
            # real in-scope contracts that MUST be authored
            "src/basin/src/Aquifer.sol",
            "src/basin/src/Well.sol",
            "src/beanstalk/protocol/contracts/SiloFacet.sol",
        ]
        for f in files:
            p = ws / f
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("contract X {}\n", encoding="utf-8")
        return ws

    def test_vendored_deps_excluded_real_contracts_selected(self):
        ws = self._mkws()
        # cap of 3 - the bug authored 3 forge-std libs; the fix must author 3 real contracts
        picked = _author_find(ws, cap=3)
        self.assertTrue(picked, "find returned nothing")
        for p in picked:
            self.assertNotIn("/lib/", p, f"vendored lib leaked into author set: {p}")
            self.assertNotIn("forge-std", p, f"forge-std leaked into author set: {p}")
            self.assertNotIn("node_modules", p, f"node_modules leaked: {p}")
            self.assertNotIn("/out/", p, f"build out/ leaked: {p}")
        # the real contracts are what gets authored
        self.assertTrue(any("src/Aquifer.sol" in p or "src/Well.sol" in p
                            or "SiloFacet.sol" in p for p in picked),
                        f"no real in-scope contract selected: {picked}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
