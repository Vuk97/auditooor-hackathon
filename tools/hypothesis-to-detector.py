#!/usr/bin/env python3
"""hypothesis-to-detector.py — natural-language hypothesis → draft DSL
pattern (Phase 31 of PR #84).

The operator feeds a one-line bug *hypothesis* (prose English) and a
kebab-case class name. This tool does a best-effort lexical pass over
the hypothesis, extracts function-name / body-shape / anti-pattern
candidates, then emits:

    reference/patterns.dsl/HYPOTHESIS-<class>.yaml
    patterns/fixtures/HYPOTHESIS-<class>_vuln.sol
    patterns/fixtures/HYPOTHESIS-<class>_clean.sol

…each populated with inline ``# TODO (inferred from hypothesis: "<quote>")``
markers so the reviewer can see *why* each predicate was generated and
flip it to something real in under five minutes.

This is NOT a real NL parser. It is a reviewer prompt — a better
starting point than ``new-detector-wizard.py`` when the operator has
only a prose suspicion and wants the yaml/fixture skeleton in one
shot. The emitted files are prefixed ``HYPOTHESIS-`` so the compile
pipeline (``make compile``) will skip them until the operator renames.

Usage:
    tools/hypothesis-to-detector.py \\
        --hypothesis "Vault.withdraw reads balanceOf(this) as totalAssets but the contract can receive donations that inflate shares" \\
        --class vault-donation-share-inflation

Flags:
    --hypothesis TEXT   prose bug suspicion (required)
    --class KEBAB       kebab-case class stem (required)
    --force             overwrite existing HYPOTHESIS-* files

Pure stdlib. No compile. No git. Review-then-rename-then-compile.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parent.parent
YAML_DIR = ROOT / "reference" / "patterns.dsl"
FIX_DIR = ROOT / "patterns" / "fixtures"
CORRELATOR = ROOT / "tools" / "exploit-chain-correlator.py"

# ─── Lexical helpers ───────────────────────────────────────────────────────

# `Vault.withdraw`, `ERC4626.deposit`, etc.
RE_QUALIFIED = re.compile(r"\b([A-Z][A-Za-z0-9]*)\.([a-z][A-Za-z0-9]*)\b")

# Bare verbs that name solidity entrypoints. Conservative list — extend
# only when a hypothesis in the wild fails to hit something obvious.
FN_VERBS = {
    "deposit", "withdraw", "mint", "burn", "redeem", "claim", "stake",
    "unstake", "transfer", "transferfrom", "approve", "swap", "borrow",
    "repay", "liquidate", "flashloan", "execute", "initialize", "rebase",
    "harvest", "compound", "settle", "rescue", "migrate", "upgrade",
    "pause", "unpause", "sweep", "donate",
}

# Body-shape anchors — literal solidity fragments readers often cite.
# Each tuple is (canonical-regex, human-tag-for-the-todo-comment).
BODY_SHAPES = [
    (r"balanceOf\s*\(\s*(?:address\s*\(\s*this\s*\)|this)\s*\)", "balanceOf(this)"),
    (r"totalSupply\s*\(\s*\)", "totalSupply()"),
    (r"totalAssets\s*\(\s*\)", "totalAssets()"),
    (r"_mint\b", "_mint"),
    (r"_burn\b", "_burn"),
    (r"\btransfer\s*\(", "transfer("),
    (r"\bsafeTransfer\b", "safeTransfer"),
    (r"\bcall\s*\{\s*value", "call{value:"),
    (r"\bdelegatecall\b", "delegatecall"),
    (r"\bmsg\.sender\b", "msg.sender"),
    (r"\btx\.origin\b", "tx.origin"),
    (r"\bblock\.timestamp\b", "block.timestamp"),
    (r"\babi\.encodePacked\b", "abi.encodePacked"),
    (r"\becrecover\b", "ecrecover"),
]

# Anti-pattern phrases — if any of these hits the hypothesis text, we
# emit a `not_body_contains_regex` predicate so the reviewer can plug
# in the actual mitigation literal.
ANTI_CUES = [
    ("without checking", "require|if\\s*\\("),
    ("no require", "require\\b"),
    ("missing validation", "require|revert\\b"),
    ("missing check", "require|if\\s*\\("),
    ("no slippage", "minOut|minAmount|slippage"),
    ("no deadline", "deadline\\b"),
    ("no access control", "onlyOwner|onlyRole|_checkRole|authorised|authorized"),
    ("not authenticated", "onlyOwner|onlyRole|_checkRole|msg\\.sender\\s*==\\s*owner"),
    ("missing reentrancy", "nonReentrant|ReentrancyGuard"),
    ("no reentrancy guard", "nonReentrant|ReentrancyGuard"),
    ("unbounded loop", "break\\b|i\\s*<\\s*MAX"),
    ("no pause", "whenNotPaused|paused\\(\\)"),
]

# Source-regex cues ("vault" → Vault|ERC4626|…). These feed
# contract.source_matches_regex.
CONTRACT_CUES = [
    ("vault", r"Vault|ERC4626|IERC4626"),
    ("erc4626", r"ERC4626|IERC4626"),
    ("token", r"ERC20|IERC20|Token"),
    ("erc20", r"ERC20|IERC20"),
    ("erc721", r"ERC721|IERC721"),
    ("nft", r"ERC721|ERC1155"),
    ("lending", r"Pool|LendingPool|Market|Comptroller"),
    ("staking", r"Staking|Stake|RewardPool"),
    ("bridge", r"Bridge|Portal|Messenger"),
    ("amm", r"Pair|Pool|Router"),
    ("oracle", r"Oracle|PriceFeed|AggregatorV3"),
    ("gauge", r"Gauge|Voter"),
    ("governor", r"Governor|Timelock|Voting"),
]


# ─── Parsing ───────────────────────────────────────────────────────────────


def short(text: str, n: int = 60) -> str:
    """Trim a quote for use in a TODO comment."""
    t = " ".join(text.split())
    return (t[: n - 1] + "…") if len(t) > n else t


def extract_functions(hypothesis: str) -> list[tuple[str, str]]:
    """Return [(fn_name_lower, source_quote)] tuples."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    # Qualified: `Vault.withdraw`
    for m in RE_QUALIFIED.finditer(hypothesis):
        fn = m.group(2).lower()
        if fn not in seen:
            seen.add(fn)
            out.append((fn, m.group(0)))

    # Bare verbs
    for tok in re.findall(r"\b([a-zA-Z][a-zA-Z0-9_]*)\b", hypothesis):
        lo = tok.lower()
        if lo in FN_VERBS and lo not in seen:
            seen.add(lo)
            out.append((lo, tok))
    return out


def extract_body_shapes(hypothesis: str) -> list[tuple[str, str]]:
    """Return [(regex, tag)] for each BODY_SHAPES hit."""
    out: list[tuple[str, str]] = []
    for regex, tag in BODY_SHAPES:
        # The hypothesis is prose; match the tag literally (case-insensitive)
        # or the regex itself if the writer pasted solidity verbatim.
        if re.search(re.escape(tag), hypothesis, re.IGNORECASE) or re.search(
            regex, hypothesis, re.IGNORECASE
        ):
            out.append((regex, tag))
    return out


def extract_anti_patterns(hypothesis: str) -> list[tuple[str, str]]:
    lo = hypothesis.lower()
    out: list[tuple[str, str]] = []
    for cue, regex in ANTI_CUES:
        if cue in lo:
            out.append((regex, cue))
    return out


def extract_contract_scope(hypothesis: str) -> tuple[str, list[str]]:
    """Return (regex, matched_cue_tags)."""
    lo = hypothesis.lower()
    hits = [(cue, regex) for cue, regex in CONTRACT_CUES if cue in lo]
    if not hits:
        return ".*", []
    regex = "|".join(r for _, r in hits)
    return regex, [cue for cue, _ in hits]


def _bug_classes_keys() -> list[str]:
    """Best-effort parse of BUG_CLASSES keys from parity-report.py.

    Correlator --analogical searches that corpus, so our seed must live
    there. Returns [] if the file is missing or unparseable.
    """
    parity = ROOT / "tools" / "parity-report.py"
    try:
        src = parity.read_text()
    except OSError:
        return []
    return re.findall(r'^\s{4}"([a-z0-9][a-z0-9\-]*)"\s*:\s*\{', src, re.MULTILINE)


def _pick_seed_detector(class_name: str, hypothesis: str) -> str | None:
    """Pick the best BUG_CLASSES key (or yaml stem as fallback) to seed
    correlator --analogical. Tokenises class_name + hypothesis, ranks
    candidates by token overlap, returns the top one."""
    tokens = {
        t for t in re.findall(r"[a-z]{4,}", (class_name + " " + hypothesis).lower())
    }
    if not tokens:
        return None
    candidates = _bug_classes_keys()
    if not candidates:
        try:
            candidates = [p.stem for p in YAML_DIR.glob("*.yaml")
                          if not p.stem.startswith("HYPOTHESIS-")]
        except OSError:
            return None
    best: tuple[int, str] | None = None
    for name in candidates:
        nt = set(re.findall(r"[a-z]{4,}", name.lower()))
        overlap = len(tokens & nt)
        if overlap >= 2 and (best is None or overlap > best[0]):
            best = (overlap, name)
    return best[1] if best else None


def _inline_analogs(class_name: str, hypothesis: str, top: int = 3) -> list[str]:
    """Fallback token-overlap scan over yaml filenames. Used only when
    the correlator subprocess fails or times out."""
    tokens = {
        t for t in re.findall(r"[a-z]{4,}", (class_name + " " + hypothesis).lower())
    }
    if not tokens:
        return []
    scored: list[tuple[int, str]] = []
    try:
        names = [p.stem for p in YAML_DIR.glob("*.yaml")
                 if not p.stem.startswith("HYPOTHESIS-")]
    except OSError:
        return []
    for name in names:
        nt = set(re.findall(r"[a-z]{4,}", name.lower()))
        overlap = len(tokens & nt)
        if overlap >= 2:
            scored.append((overlap, name))
    scored.sort(reverse=True)
    return [name for _, name in scored[:top]]


def analogical_hints(class_name: str, hypothesis: str, top: int = 3,
                     timeout: float = 15.0) -> list[str]:
    """Find analogical neighbours.

    Primary path: pick a seed detector (best token match against existing
    pattern stems), then delegate to ``exploit-chain-correlator.py
    --analogical <seed> --export-json``. That tool runs a TF-IDF cosine
    search over the BUG_CLASSES corpus and is sharper than filename
    token-overlap.

    Fallback path: if the correlator binary is missing, errors, or times
    out, silently degrade to the inline token-overlap scan.
    """
    seed = _pick_seed_detector(class_name, hypothesis)
    if seed and CORRELATOR.exists():
        try:
            result = subprocess.run(
                [sys.executable, str(CORRELATOR),
                 "--analogical", seed, "--export-json"],
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                payload = json.loads(result.stdout)
                analogs = payload.get("analogs") or []
                names = [a["detector"] for a in analogs if a.get("detector")]
                if names:
                    return names[:top]
        except (subprocess.TimeoutExpired, subprocess.SubprocessError,
                json.JSONDecodeError, OSError):
            pass  # fall through to inline scan
    return _inline_analogs(class_name, hypothesis, top=top)


# ─── Emission ──────────────────────────────────────────────────────────────


def render_yaml(
    class_name: str,
    hypothesis: str,
    contract_regex: str,
    contract_cues: list[str],
    fns: list[tuple[str, str]],
    shapes: list[tuple[str, str]],
    antis: list[tuple[str, str]],
    analogs: list[str],
) -> str:
    q = short(hypothesis, 90)
    fn_names = "|".join(fn for fn, _ in fns) or "TODO_fn_name"
    lines: list[str] = []
    lines.append(f"# DRAFT from hypothesis-to-detector.py — review before compile.")
    lines.append(f"# Hypothesis: {q}")
    if analogs:
        lines.append(f"# Analogical neighbours (correlator TF-IDF): {', '.join(analogs)}")
    lines.append(f"pattern: HYPOTHESIS-{class_name}")
    lines.append("source: hypothesis-to-detector")
    lines.append("severity: TODO   # reviewer: HIGH | MEDIUM | LOW")
    lines.append("confidence: LOW  # starts LOW until fixtures green")
    lines.append("")
    lines.append("preconditions:")
    cue_tag = ",".join(contract_cues) if contract_cues else "no-scope-cue"
    lines.append(
        f"  # TODO (inferred from hypothesis cues: {cue_tag})"
    )
    lines.append(f"  - contract.source_matches_regex: '{contract_regex}'")
    lines.append("")
    lines.append("match:")
    lines.append("  - function.kind: external_or_public")
    lines.append("  - function.not_slither_synthetic: true")
    lines.append("  - function.is_mutating: true")

    if fns:
        fn_quotes = ", ".join(f'"{q_}"' for _, q_ in fns)
        lines.append(f"  # TODO (inferred from hypothesis tokens: {fn_quotes})")
    else:
        lines.append("  # TODO (no function-name candidate found — fill in)")
    lines.append(f"  - function.name_matches: '{fn_names}'")

    if shapes:
        for regex, tag in shapes:
            lines.append(f"  # TODO (inferred from body-shape cue: {tag})")
            lines.append(f"  - function.body_contains_regex: '{regex}'")
    else:
        lines.append(
            "  # TODO (no body-shape cue found — add a positive body anchor)"
        )
        lines.append("  - function.body_contains_regex: 'TODO_positive_anchor'")

    if antis:
        for regex, cue in antis:
            lines.append(
                f"  # TODO (inferred from anti-pattern cue: \"{cue}\" — fill real mitigation)"
            )
            lines.append(f"  - function.not_body_contains_regex: '{regex}'")
    else:
        lines.append(
            "  # TODO (no explicit anti-pattern cue — add mitigation regex if any)"
        )
        lines.append("  # - function.not_body_contains_regex: 'TODO_mitigation'")

    lines.append("  - function.not_in_skip_list: true")
    lines.append("  - function.not_leaf_helper: true")
    lines.append("  - function.not_source_matches_regex: '(?i)mock|test|fixture'")
    lines.append("")
    lines.append("fixtures:")
    lines.append(f"  vuln: patterns/fixtures/HYPOTHESIS-{class_name}_vuln.sol")
    lines.append(f"  clean: patterns/fixtures/HYPOTHESIS-{class_name}_clean.sol")
    lines.append("")
    lines.append(f'help: "DRAFT — {q}"')
    lines.append(f'wiki_title: "TODO title for {class_name}"')
    lines.append(f'wiki_description: "TODO — start from hypothesis: {q}"')
    lines.append('wiki_exploit_scenario: "TODO — concrete attack walkthrough."')
    lines.append('wiki_recommendation: "TODO — canonical mitigation."')
    lines.append("")
    return "\n".join(lines) + "\n"


def render_fixture(class_name: str, hypothesis: str, kind: str,
                   fns: list[tuple[str, str]]) -> str:
    fn = fns[0][0] if fns else "victimFn"
    tag = "VULNERABLE" if kind == "vuln" else "SAFE"
    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DRAFT {tag} fixture — auto-scaffolded by hypothesis-to-detector.py
// Hypothesis: {short(hypothesis, 110)}
//
// TODO reviewer:
//   1. Rename file + pattern: (strip the HYPOTHESIS- prefix when ready).
//   2. Flesh out the function body so it actually triggers / evades
//      the YAML predicates.
//   3. `make compile && make test` should show this fixture toggling
//      the detector exactly once (vuln green, clean green).

contract Hypothesis_{class_name.replace("-", "_")}_{kind} {{
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function {fn}(uint256 amount) external {{
        // TODO ({tag}): write the minimal body that demonstrates
        // {"the bug" if kind == "vuln" else "the canonical mitigation"}.
        amount; // silence unused-var warning
    }}
}}
"""


# ─── Main ──────────────────────────────────────────────────────────────────


def print_checklist(class_name: str, yaml_path: Path, vuln_path: Path,
                    clean_path: Path, analogs: list[str]) -> None:
    print()
    print("── Review checklist " + "─" * 40)
    print(f"  [ ] Open {yaml_path.relative_to(ROOT)}")
    print("  [ ] Replace every `TODO` marker (search: 'TODO')")
    print("  [ ] Verify contract.source_matches_regex actually scopes")
    print("  [ ] Verify function.name_matches covers the real surface")
    print("  [ ] Verify body_contains_regex hits the bug shape, not prose")
    print("  [ ] Fill the not_body_contains_regex with the real mitigation")
    print(f"  [ ] Flesh out {vuln_path.relative_to(ROOT)} to trigger the match")
    print(f"  [ ] Flesh out {clean_path.relative_to(ROOT)} to bypass the match")
    print(f"  [ ] Strip the HYPOTHESIS- prefix from file + pattern: key")
    print("  [ ] `make compile` → `make test` → inspect parity report")
    if analogs:
        print()
        print("Analogical neighbours worth cribbing from:")
        for a in analogs:
            print(f"  - reference/patterns.dsl/{a}.yaml")
    print()
    print("When fixtures are green, this pattern joins the registry.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--hypothesis", required=True, help="prose bug suspicion")
    ap.add_argument("--class", dest="class_name", required=True,
                    help="kebab-case class stem")
    ap.add_argument("--force", action="store_true",
                    help="overwrite existing HYPOTHESIS-* files")
    ap.add_argument("--analogical-only", action="store_true",
                    help="print just the correlator neighbours list (no DSL draft)")
    args = ap.parse_args(argv)

    cls = args.class_name.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", cls):
        print(f"[hypothesis] --class must be kebab-case; got {cls!r}",
              file=sys.stderr)
        return 2

    hypothesis = args.hypothesis.strip()
    if not hypothesis:
        print("[hypothesis] --hypothesis is empty", file=sys.stderr)
        return 2

    fns = extract_functions(hypothesis)
    shapes = extract_body_shapes(hypothesis)
    antis = extract_anti_patterns(hypothesis)
    contract_regex, contract_cues = extract_contract_scope(hypothesis)
    analogs = analogical_hints(cls, hypothesis)

    if args.analogical_only:
        if not analogs:
            print("[hypothesis] no analogical neighbours found", file=sys.stderr)
            return 1
        seed = _pick_seed_detector(cls, hypothesis)
        print(f"# seed detector: {seed or '(none)'}")
        for name in analogs:
            print(name)
        return 0

    yaml_path = YAML_DIR / f"HYPOTHESIS-{cls}.yaml"
    vuln_path = FIX_DIR / f"HYPOTHESIS-{cls}_vuln.sol"
    clean_path = FIX_DIR / f"HYPOTHESIS-{cls}_clean.sol"

    for p in (yaml_path, vuln_path, clean_path):
        if p.exists() and not args.force:
            print(f"[hypothesis] refuse to overwrite {p} (use --force)",
                  file=sys.stderr)
            return 1

    YAML_DIR.mkdir(parents=True, exist_ok=True)
    FIX_DIR.mkdir(parents=True, exist_ok=True)

    yaml_text = render_yaml(cls, hypothesis, contract_regex, contract_cues,
                            fns, shapes, antis, analogs)
    yaml_path.write_text(yaml_text)
    vuln_path.write_text(render_fixture(cls, hypothesis, "vuln", fns))
    clean_path.write_text(render_fixture(cls, hypothesis, "clean", fns))

    print(f"[hypothesis] wrote {yaml_path.relative_to(ROOT)}")
    print(f"[hypothesis] wrote {vuln_path.relative_to(ROOT)}")
    print(f"[hypothesis] wrote {clean_path.relative_to(ROOT)}")

    print()
    print("── Inferred predicates ────────────────────────────────────")
    print(f"  contract.source_matches_regex : {contract_regex}"
          + (f"  (cues: {', '.join(contract_cues)})" if contract_cues else ""))
    print(f"  function.name_matches         : "
          f"{'|'.join(fn for fn, _ in fns) if fns else '(none — FILL)'}"
          )
    print(f"  body_contains_regex           : "
          f"{', '.join(tag for _, tag in shapes) if shapes else '(none — FILL)'}"
          )
    print(f"  not_body_contains_regex       : "
          f"{', '.join(cue for _, cue in antis) if antis else '(none)'}"
          )

    print_checklist(cls, yaml_path, vuln_path, clean_path, analogs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
