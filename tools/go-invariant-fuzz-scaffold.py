#!/usr/bin/env python3
"""go-invariant-fuzz-scaffold.py - the Go/Cosmos equivalent of the EVM
auto-invariant-harness-gen.py.

WHY: on a Go/Cosmos L1 the value-movers (x/bank, x/staking, x/distribution,
x/oracle, precompiles, IBC keepers, cosmwasm) are Go, so the Solidity invariant
engines (halmos / echidna / medusa) do NOT apply. The genuine equivalent is Go
NATIVE coverage-guided fuzzing (`go test -fuzz`, Go 1.18+): a `Fuzz*` target that
decodes the fuzzed byte corpus into an action-diverse op SEQUENCE over the REAL
App-bound keeper and asserts a conservation/authorization invariant after every op.
Any violation => t.Fatalf => go test minimizes a counterexample into testdata/fuzz/
(a candidate FINDING). This is first-class alongside echidna/medusa - the same
"build a real harness over the real CUT and actually fuzz it" bar.

WHAT THIS EMITS: a compiling *skeleton* `<name>_fuzz_test.go` next to the target
package, carrying the PROVEN scaffold (SEI 2026-07-05 bank_supply proof:
KeeperTestSuite App-bind + f.Add seed corpus + f.Fuzz(func(t, data)) byte-decode
loop) with THREE clearly-marked ``// SWAP:`` sections the author fills per target:
the keeper handle, the op-decode table, and the conservation/auth oracle. Plus the
exact run command and a persisted campaign OBLIGATION the invariant-fuzz gate reads.

THROUGHPUT (the load-bearing detail): a naive `f.Fuzz` body that rebuilds the whole
App via app.Setup per exec gets ~4s/exec (SEI proof: 30 execs in 120s) - enough to
PROVE binding + coverage-guided mutation, NOT a real >=1M-equivalent campaign. The
scaffold therefore hoists the heavy App bind into a package-level sync.Once and
resets ONLY the fuzzed module's state per exec (the author wires the reset), so a
fuzztime-bounded campaign reaches 10^4-10^5+ execs. The gate credits the go-native
campaign by fuzztime + coverage-growth evidence (App-bound throughput is lower than
in-EVM medusa, so the bar is coverage-guided-with-growth, not a raw 1M count).

CLI:
  python3 tools/go-invariant-fuzz-scaffold.py --workspace <ws> \
      --package <relpath-under-src> --name <InvName> [--suite KeeperTestSuite] \
      [--fuzztime 300s] [--emit]

Without --emit it prints the skeleton + run command to stdout (dry run). With
--emit it writes the file (never overwrites an existing one) + the obligation.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "auditooor.go_fuzz_obligation.v1"
OBLIGATION_NAME = "go_fuzz_obligations.json"

_SKELETON = '''package {pkg_name}

// {fname}_fuzz_test.go - Go-NATIVE coverage-guided invariant fuzz (the go test
// -fuzz analogue of echidna/medusa) over the REAL App-bound {target} value-mover.
// Scaffolded by tools/go-invariant-fuzz-scaffold.py; SWAP the 3 marked sections.
//
// RUN (a real campaign, not a smoke loop):
//   cd <src-root> && GOTOOLCHAIN=go1.25.8 go test ./{pkg_rel}/ \\
//       -run=^$ -fuzz={fuzzfn} -fuzztime={fuzztime}
// A counterexample is minimized into testdata/fuzz/{fuzzfn}/ = a candidate FINDING.

import (
	"sync"
	"testing"
)

// THROUGHPUT: bind the heavy App ONCE, reset only the target module's state per
// exec. A per-exec app.Setup is ~seconds/exec (proves binding, not a campaign);
// this shared-App pattern reaches 10^4-10^5+ execs in a fuzztime-bounded run.
var {fuzzfn}_once sync.Once

// {fuzzfn} drives the real App-bound {target} keeper with a coverage-guided,
// action-diverse op sequence and asserts the invariant after EVERY op.
func {fuzzfn}(f *testing.F) {{
	// Seed corpus: action-diverse byte strings that already hit the value-moving
	// branches, so the coverage-guided engine mutates outward from real coverage.
	f.Add([]byte{{0x00, 0x64}})
	f.Add([]byte{{0x00, 0xff, 0x11, 0x20, 0x22, 0x08}})
	f.Add([]byte{{0x11, 0x11, 0x22, 0x22, 0x33, 0x33}})

	f.Fuzz(func(t *testing.T, data []byte) {{
		// SWAP-1 (keeper handle): bind the REAL App keeper (NO mock - a mock that
		// delivers fabricated values is vacuity). Use the repo's own apptesting
		// helper, e.g. a fresh {suite} with SetT(t)+SetupTest(), OR a sync.Once
		// shared App reset to a clean per-fuzz state. Example (bank proof):
		//   suite := new({suite}); suite.SetT(t); suite.SetupTest()
		//   keeper := suite.App.<Keeper>

		// SWAP-3 (oracle ledger): an INDEPENDENT expected-value ledger that never
		// reads the CUT's own state to derive its expectation. Example:
		//   expected := sdk.ZeroInt()   // mints-minus-burns, escrow, rightful-share

		const maxOps = 64
		ops := 0
		for i := 0; i+1 < len(data) && ops < maxOps; i += 2 {{
			action := data[i] & 0x03
			amt := int64(data[i+1]) + 1
			_ = action
			_ = amt
			// SWAP-2 (op-decode table): map `action` to a value-moving primitive
			// (mint/burn/send/delegate/undelegate/escrow/withdraw...), bound `amt`
			// to the live holder balance so the op is a value-moving SUCCESS not a
			// trivial revert, execute against the real keeper, then assert the
			// invariant vs the SWAP-3 oracle. Any violation:
			//   t.Fatalf("INV-x violated at op %d: ...", ops)
			ops++
		}}
	}})
}}
'''


def _pkg_name(pkg_rel: str) -> str:
    # cosmos keeper tests live in `<pkg>_test`; default to the leaf dir + _test.
    leaf = pkg_rel.rstrip("/").split("/")[-1] or "pkg"
    return f"{leaf}_test"


def build_skeleton(pkg_rel: str, name: str, suite: str, fuzztime: str) -> str:
    fuzzfn = f"FuzzEconomicInvariant_{name}"
    fname = name.lower()
    return _SKELETON.format(
        pkg_name=_pkg_name(pkg_rel), fname=fname, fuzzfn=fuzzfn,
        pkg_rel=pkg_rel.rstrip("/"), suite=suite, target=name, fuzztime=fuzztime,
    )


def _write_obligation(ws: Path, pkg_rel: str, name: str, fuzztime: str,
                      harness_path: str) -> Path:
    adir = ws / ".auditooor"
    adir.mkdir(parents=True, exist_ok=True)
    path = adir / OBLIGATION_NAME
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    data.setdefault("schema", SCHEMA)
    obligs = data.setdefault("obligations", [])
    fuzzfn = f"FuzzEconomicInvariant_{name}"
    if not any(o.get("fuzz_fn") == fuzzfn for o in obligs):
        obligs.append({
            "fuzz_fn": fuzzfn, "package": pkg_rel, "harness_path": harness_path,
            "fuzztime": fuzztime, "engine": "go-native-coverage-guided-fuzz",
            "status": "scaffolded-awaiting-campaign",
        })
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scaffold a Go-native coverage-guided invariant-fuzz harness")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--package", required=True, help="package relpath under the source root, e.g. x/bank/keeper")
    ap.add_argument("--name", required=True, help="invariant name, e.g. BankSupply (-> FuzzEconomicInvariant_BankSupply)")
    ap.add_argument("--suite", default="KeeperTestSuite")
    ap.add_argument("--fuzztime", default="300s")
    ap.add_argument("--src-root", default="src/sei-chain", help="source root under the workspace")
    ap.add_argument("--emit", action="store_true", help="write the file + obligation (else dry-run to stdout)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()
    skel = build_skeleton(args.package, args.name, args.suite, args.fuzztime)
    fname = args.name.lower()
    rel = f"{args.src_root.rstrip('/')}/{args.package.rstrip('/')}/{fname}_fuzz_test.go"
    out = ws / rel
    fuzzfn = f"FuzzEconomicInvariant_{args.name}"
    run_cmd = (f"cd {ws / args.src_root} && GOTOOLCHAIN=go1.25.8 go test "
               f"./{args.package.rstrip('/')}/ -run=^$ -fuzz={fuzzfn} -fuzztime={args.fuzztime}")

    if not args.emit:
        print(f"# DRY RUN - would write {rel}\n")
        print(skel)
        print(f"\n# RUN THE CAMPAIGN:\n{run_cmd}")
        return 0

    if out.exists():
        print(f"[go-invariant-fuzz-scaffold] REFUSING to overwrite existing {rel}", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(skel, encoding="utf-8")
    obl = _write_obligation(ws, args.package, args.name, args.fuzztime, rel)
    print(f"[go-invariant-fuzz-scaffold] wrote {rel}")
    print(f"[go-invariant-fuzz-scaffold] obligation -> {obl.relative_to(ws)}")
    print(f"[go-invariant-fuzz-scaffold] RUN: {run_cmd}")
    print("[go-invariant-fuzz-scaffold] fill the 3 SWAP sections, run the campaign, "
          "then emit an mvc_sidecar (engine=go-native-coverage-guided-fuzz, campaign_calls, fuzztime).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
