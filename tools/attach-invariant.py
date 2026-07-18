#!/usr/bin/env python3
"""PR 110 + PR 203 + PR 203-b + capv3 iter-001 T4 — attach canonical invariant template(s).

PR 110 (generic):
  Copies the Candidate-witness-test Foundry skeleton extracted from
  `reference/invariants/<slug>.md` into
  `<workspace>/poc-tests/invariants/Invariant<Slug>.t.sol`, substituting
  the `{CONTRACT}` placeholder if `--contract` is provided.
  Refuses to overwrite an existing destination file.

PR 203 / PR 203-b (protocol-family, v2):
  --family <amm|vault|lending|bridge|governance>
                                  copy every .t.sol in the family dir
                                  into <ws>/poc-tests/invariants/. These
                                  are *candidate harnesses*, not proof —
                                  a runner must execute them and record
                                  a concrete status in the evidence
                                  matrix before anyone cites a pass.

  --suggest-family                scan <ws>/src/**/*.sol for family
                                  signature patterns and print a ranked
                                  list. Always prints every family with
                                  a score; returns "no confident
                                  suggestion" when every family scores
                                  zero (cannot-judge behaviour).

  --contract <Name>               replace `{ContractName}` (v2 families)
                                  or `{CONTRACT}` (v1 generics) with
                                  `<Name>` in every written file. Left
                                  as-is if no --contract is supplied.

capv3 iter-001 T4 (campaign):
  --mode campaign --family vault  auto-detect ERC4626 and emit five
                                  concrete, compilable invariant
                                  harnesses to <ws>/poc-tests/invariants/
                                  (vault_campaign_I1..I5.t.sol). Refuses
                                  on a non-ERC4626 contract (hard
                                  negative). See
                                  tools/invariants/campaign/vault_erc4626.py
                                  for harness bodies.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INVARIANTS_DIR = REPO / "reference" / "invariants"
MANIFEST = INVARIANTS_DIR / "MANIFEST.json"

# PR 203: protocol-family templates live here.
FAMILIES_DIR = REPO / "tools" / "invariants" / "families"
KNOWN_FAMILIES = ("amm", "vault", "lending", "bridge", "governance")

# capv3 iter-001 T4: families that ship a runnable --mode campaign emitter.
# Loaded lazily at use-site.
CAMPAIGN_FAMILIES = ("vault",)

WITNESS_RE = re.compile(
    r"##\s+Candidate witness test\s*\n+```solidity\s*\n(?P<body>.*?)\n```",
    re.DOTALL,
)

# PR 203: signature-pattern heuristics for --suggest-family.
#
# Each entry is (family, weight, regex). Weight lets strong signals
# (e.g. `getReserves()` is near-pathognomonic for a UniV2-shape AMM)
# outvote weaker ones (e.g. `swap(` alone). All regexes are matched
# case-insensitively with re.MULTILINE.
FAMILY_SIGNATURES: list[tuple[str, int, str]] = [
    # --- AMM ---
    ("amm", 4, r"\bfunction\s+getReserves\s*\("),
    ("amm", 3, r"\bfunction\s+swap\s*\([^)]*\)"),
    ("amm", 3, r"\bfunction\s+addLiquidity\s*\("),
    ("amm", 3, r"\bfunction\s+removeLiquidity\s*\("),
    ("amm", 2, r"\bfunction\s+mint\s*\(\s*address\s+\w+\s*\)"),  # UniV2 mint
    ("amm", 2, r"\bfunction\s+burn\s*\(\s*address\s+\w+\s*\)"),  # UniV2 burn
    ("amm", 2, r"\breserve0\b"),
    ("amm", 2, r"\breserve1\b"),
    ("amm", 2, r"\bkLast\b"),
    # --- ERC4626 / Vault ---
    ("vault", 4, r"\bfunction\s+convertToShares\s*\("),
    ("vault", 4, r"\bfunction\s+convertToAssets\s*\("),
    ("vault", 3, r"\bfunction\s+totalAssets\s*\("),
    ("vault", 3, r"\bfunction\s+previewDeposit\s*\("),
    ("vault", 3, r"\bfunction\s+previewRedeem\s*\("),
    ("vault", 3, r"\bfunction\s+deposit\s*\([^)]*receiver"),
    ("vault", 3, r"\bfunction\s+redeem\s*\([^)]*receiver"),
    ("vault", 2, r"\bIERC4626\b"),
    ("vault", 2, r"\bERC4626\b"),
    # --- Lending ---
    ("lending", 4, r"\bfunction\s+liquidate(?:Borrow|Position)?\s*\("),
    ("lending", 3, r"\bfunction\s+borrow\s*\("),
    ("lending", 3, r"\bfunction\s+repayBorrow\w*\s*\("),
    ("lending", 3, r"\bfunction\s+accrueInterest\s*\("),
    ("lending", 3, r"\bfunction\s+getAccountLiquidity\s*\("),
    ("lending", 2, r"\bcollateralFactor\w*\b"),
    ("lending", 2, r"\bborrowIndex\b"),
    ("lending", 2, r"\bbadDebt\b"),
    ("lending", 2, r"\bLTV\b"),
    ("lending", 2, r"\bhealthFactor\b"),
    # --- Bridge (PR 203-b) ---
    # Strong signals: cross-chain entry points / inbox-style consumers.
    ("bridge", 4, r"\bbridgeFromChain\s*\("),
    ("bridge", 4, r"\bsendMessage\s*\("),
    ("bridge", 4, r"\bIL1CrossDomainMessenger\b"),
    ("bridge", 4, r"\bprocessMessage\s*\("),
    ("bridge", 4, r"\bconsume(?:\w*Message)?\s*\("),
    # Weaker supporting signals — structure without committing to a
    # specific vendor.
    ("bridge", 2, r"\bfinalizeWithdrawal\w*\s*\("),
    ("bridge", 2, r"\brelayMessage\s*\("),
    ("bridge", 2, r"\bnonce\b.*\bmessage\b"),
    # --- Governance (PR 203-b) ---
    ("governance", 4, r"\bpropose\s*\("),
    ("governance", 4, r"\bqueue\s*\("),
    ("governance", 4, r"\bcastVote\w*"),
    ("governance", 4, r"\bquorum\s*\("),
    ("governance", 4, r"\btimelock\b"),
    ("governance", 2, r"\bproposalSnapshot\s*\("),
    ("governance", 2, r"\bminDelay\b"),
    ("governance", 2, r"\bGovernor\w*\b"),
]


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def slug_to_pascal(slug: str) -> str:
    return "".join(part.capitalize() for part in re.split(r"[-_]", slug))


def extract_witness(md_path: Path) -> str:
    text = md_path.read_text()
    m = WITNESS_RE.search(text)
    if not m:
        raise RuntimeError(
            f"[attach-invariant] no candidate witness test block found in {md_path}"
        )
    return m.group("body").rstrip() + "\n"


# ---------------------------------------------------------------------------
# PR 203: protocol-family helpers
# ---------------------------------------------------------------------------


def family_dir(family: str) -> Path:
    return FAMILIES_DIR / family


def list_family_templates(family: str) -> list[Path]:
    d = family_dir(family)
    if not d.is_dir():
        return []
    return sorted(d.glob("*.t.sol"))


def _iter_sol_files(ws_src: Path):
    if not ws_src.is_dir():
        return
    yield from ws_src.rglob("*.sol")


def score_families(ws: Path) -> dict[str, int]:
    """Return {family: score} after scanning ws/src/**/*.sol."""
    scores = {f: 0 for f in KNOWN_FAMILIES}
    src = ws / "src"
    compiled = [
        (fam, w, re.compile(pat, re.IGNORECASE | re.MULTILINE))
        for (fam, w, pat) in FAMILY_SIGNATURES
    ]
    for sol in _iter_sol_files(src):
        try:
            text = sol.read_text(errors="replace")
        except OSError:
            continue
        for fam, weight, rx in compiled:
            if rx.search(text):
                scores[fam] += weight
    return scores


def suggest_family(ws: Path) -> tuple[list[tuple[str, int]], str | None]:
    """Return (ranked, best). `best` is None when every score is zero."""
    scores = score_families(ws)
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    best = ranked[0][0] if ranked and ranked[0][1] > 0 else None
    return ranked, best


def copy_family(
    family: str, ws: Path, contract: str | None
) -> tuple[int, list[Path], list[Path]]:
    """Copy all templates in `family` into ws/poc-tests/invariants/.

    Returns (exit_code, written_paths, skipped_paths).
    Refuses to overwrite any existing file — on first collision it
    aborts without writing anything further, matching the v1 refusal
    semantics. Files written before the collision stay on disk, so
    either remove the directory or pick a new workspace before
    retrying.
    """
    templates = list_family_templates(family)
    if not templates:
        print(
            f"[attach-invariant] FAIL: family '{family}' has no templates at "
            f"{family_dir(family)}",
            file=sys.stderr,
        )
        return 2, [], []
    out_dir = ws / "poc-tests" / "invariants"
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    skipped: list[Path] = []
    for tpl in templates:
        dest = out_dir / tpl.name
        if dest.exists():
            print(
                f"[attach-invariant] FAIL: refusing to overwrite existing file: "
                f"{dest}",
                file=sys.stderr,
            )
            skipped.append(dest)
            return 1, written, skipped
        body = tpl.read_text()
        if contract:
            body = body.replace("{ContractName}", contract)
            body = body.replace("{CONTRACT}", contract)
        dest.write_text(body)
        written.append(dest)
        print(f"[attach-invariant] wrote {dest}")
    print(
        f"[attach-invariant] family={family} copied {len(written)} template(s) "
        f"(candidate harnesses — not proof)"
    )
    return 0, written, skipped


# ---------------------------------------------------------------------------
# capv3 iter-001 T4: campaign mode
# ---------------------------------------------------------------------------


def _concat_src(ws: Path) -> str:
    """Concatenate every .sol file under <ws>/src/ into one string."""
    src = ws / "src"
    if not src.is_dir():
        return ""
    buf: list[str] = []
    for sol in _iter_sol_files(src):
        try:
            buf.append(sol.read_text(errors="replace"))
        except OSError:
            continue
    return "\n".join(buf)


def _load_vault_campaign_module():
    """Load `tools/invariants/campaign/vault_erc4626.py` by file path.

    `tools/` is not a Python package (no __init__.py) so `import
    tools.invariants...` does not resolve in every environment. A
    path-based loader is robust across the CLI invocation and the
    in-process regression tests.
    """
    import importlib.util

    path = REPO / "tools" / "invariants" / "campaign" / "vault_erc4626.py"
    spec = importlib.util.spec_from_file_location(
        "auditooor_vault_erc4626", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load campaign module at {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def detect_vault(ws: Path) -> tuple[bool, list[str]]:
    """Delegate to the vault_erc4626 campaign detector."""
    mod = _load_vault_campaign_module()
    return mod.detect_erc4626(_concat_src(ws))


def emit_vault_campaign(
    ws: Path, contract: str | None
) -> tuple[int, list[Path], list[Path]]:
    """Write the 5 ERC4626 campaign harnesses into <ws>/poc-tests/invariants/.

    Returns (exit_code, written, skipped). Refuses on missing ERC4626
    methods or on any existing destination file.
    """
    mod = _load_vault_campaign_module()

    ok, missing = mod.detect_erc4626(_concat_src(ws))
    if not ok:
        print(
            "[attach-invariant] FAIL: campaign mode requires an ERC4626 "
            f"contract in <ws>/src/. Missing methods: {', '.join(missing)}",
            file=sys.stderr,
        )
        return 2, [], []

    name = contract or "Vault"
    out_dir = ws / "poc-tests" / "invariants"
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    skipped: list[Path] = []
    for fname, body in mod.INVARIANTS:
        dest = out_dir / fname
        if dest.exists():
            print(
                f"[attach-invariant] FAIL: refusing to overwrite existing file: "
                f"{dest}",
                file=sys.stderr,
            )
            skipped.append(dest)
            return 1, written, skipped
        rendered = mod.render_file(body, name)
        dest.write_text(rendered)
        written.append(dest)
        print(f"[attach-invariant] wrote {dest}")
    print(
        f"[attach-invariant] campaign vault: wrote {len(written)} runnable "
        "harness(es) (candidate — not proof until runner confirms)"
    )
    return 0, written, skipped


# ---------------------------------------------------------------------------
# capv3 iter-001 T4: campaign report aggregation
# ---------------------------------------------------------------------------


CAMPAIGN_INVARIANT_IDS = ("I1", "I2", "I3", "I4", "I5")


def summarise_campaign(
    ws: Path,
    runner,
) -> dict:
    """Run `runner(invariant_file_path) -> status_dict` for each of the 5
    campaign harnesses and aggregate into a campaign report.

    `runner` is injected so tests can mock it — production callers pass
    a thin wrapper around `tools/fuzz-runner.sh` (black-box consumer per
    the playbook, no modifications to the runner).

    Status dicts should carry at least `status` (one of `pass`,
    `counterexample`, `timeout`, `error`, `skipped`). Anything else is
    forwarded under `details`.
    """
    mod = _load_vault_campaign_module()

    out_dir = ws / "poc-tests" / "invariants"
    results: list[dict] = []
    for (fname, _body), inv_id in zip(
        mod.INVARIANTS, CAMPAIGN_INVARIANT_IDS
    ):
        path = out_dir / fname
        if not path.exists():
            results.append(
                {
                    "id": inv_id,
                    "file": str(path),
                    "status": "missing",
                    "details": {},
                }
            )
            continue
        res = runner(path)
        results.append(
            {
                "id": inv_id,
                "file": str(path),
                "status": res.get("status", "error"),
                "details": {k: v for k, v in res.items() if k != "status"},
            }
        )

    passes = sum(1 for r in results if r["status"] == "pass")
    counter = [r for r in results if r["status"] == "counterexample"]
    return {
        "family": "vault",
        "mode": "campaign",
        "total": len(results),
        "pass": passes,
        "counterexamples": [r["id"] for r in counter],
        "results": results,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Attach canonical invariant template(s) to a workspace."
    )
    parser.add_argument(
        "workspace",
        nargs="?",
        help="Path to workspace directory (optional with --list-families)",
    )
    parser.add_argument(
        "--template", default=None, help="(v1) Generic template slug"
    )
    parser.add_argument(
        "--family",
        default=None,
        help="(v2) Protocol family: amm | vault | lending | bridge | governance",
    )
    parser.add_argument(
        "--mode",
        default=None,
        choices=("scaffold", "campaign"),
        help=(
            "(capv3 T4) Emission mode. 'scaffold' (default) copies the "
            "v2 family templates; 'campaign' emits runnable harnesses "
            "against an auto-detected protocol (currently: vault)."
        ),
    )
    parser.add_argument(
        "--suggest-family",
        action="store_true",
        help="Scan workspace src/ and print a ranked family suggestion",
    )
    parser.add_argument(
        "--list-families",
        action="store_true",
        help="List known families and their template files",
    )
    parser.add_argument("--contract", default=None, help="Target contract name")
    args = parser.parse_args(argv)

    # --list-families short-circuit (workspace optional).
    if args.list_families:
        for fam in KNOWN_FAMILIES:
            tpls = list_family_templates(fam)
            print(f"{fam}: {len(tpls)} template(s)")
            for t in tpls:
                print(f"  {t.name}")
        return 0

    if not args.workspace:
        print(
            "[attach-invariant] FAIL: workspace argument required "
            "(or use --list-families)",
            file=sys.stderr,
        )
        return 2

    ws = Path(args.workspace)
    if not ws.exists():
        print(
            f"[attach-invariant] FAIL: workspace not found: {ws}", file=sys.stderr
        )
        return 2

    # --- PR 203: --suggest-family -----------------------------------------
    if args.suggest_family:
        ranked, best = suggest_family(ws)
        print("[attach-invariant] family suggestion (ranked):")
        for fam, score in ranked:
            marker = " *" if fam == best else ""
            print(f"  {fam:<8} score={score}{marker}")
        if best is None:
            print(
                "[attach-invariant] no confident suggestion — every family "
                "scored zero. Inspect src/ manually or supply --family "
                "<name> explicitly."
            )
        else:
            print(f"[attach-invariant] best guess: {best}")
        return 0

    # --- PR 203: --family -------------------------------------------------
    if args.family is not None:
        if args.family not in KNOWN_FAMILIES:
            valid = ", ".join(KNOWN_FAMILIES)
            print(
                f"[attach-invariant] FAIL: unknown family '{args.family}'. "
                f"Valid: {valid}",
                file=sys.stderr,
            )
            return 2
        # capv3 T4: campaign mode — runnable harnesses, family-specific.
        if args.mode == "campaign":
            if args.family not in CAMPAIGN_FAMILIES:
                valid = ", ".join(CAMPAIGN_FAMILIES)
                print(
                    f"[attach-invariant] FAIL: --mode campaign has no "
                    f"emitter for family '{args.family}'. Supported: {valid}",
                    file=sys.stderr,
                )
                return 2
            if args.family == "vault":
                code, _w, _s = emit_vault_campaign(ws, args.contract)
                return code
        code, _written, _skipped = copy_family(args.family, ws, args.contract)
        return code

    # capv3 T4: --mode campaign requires --family.
    if args.mode == "campaign" and args.family is None:
        print(
            "[attach-invariant] FAIL: --mode campaign requires --family "
            f"<{'|'.join(CAMPAIGN_FAMILIES)}>",
            file=sys.stderr,
        )
        return 2

    # --- PR 110: generic --template ---------------------------------------
    if not args.template:
        print(
            "[attach-invariant] FAIL: must supply one of --template, --family, "
            "--suggest-family, or --list-families",
            file=sys.stderr,
        )
        return 2

    try:
        manifest = load_manifest()
    except FileNotFoundError:
        print(f"[attach-invariant] FAIL: manifest missing at {MANIFEST}", file=sys.stderr)
        return 2

    slugs = {t["slug"]: t for t in manifest["templates"]}
    if args.template not in slugs:
        valid = ", ".join(sorted(slugs))
        print(
            f"[attach-invariant] FAIL: unknown template slug "
            f"'{args.template}'. Valid: {valid}",
            file=sys.stderr,
        )
        return 1

    entry = slugs[args.template]
    md_path = INVARIANTS_DIR / entry["path"]
    try:
        body = extract_witness(md_path)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.contract:
        body = body.replace("{CONTRACT}", args.contract)

    out_dir = ws / "poc-tests" / "invariants"
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / f"Invariant{slug_to_pascal(args.template)}.t.sol"

    if dest.exists():
        print(
            f"[attach-invariant] FAIL: refusing to overwrite existing file: {dest}",
            file=sys.stderr,
        )
        return 1

    dest.write_text(body)
    print(f"[attach-invariant] wrote {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
