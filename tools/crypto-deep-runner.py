#!/usr/bin/env python3
"""crypto-deep-runner.py - V4 P3 crypto deep-profile runner (Tier-B advisory).

Background
----------
`docs/ROADMAP_10_OF_10_V4.md` Section 2 Workstream C ("Crypto And Proof-System
Soundness") and Section 4 P3 ("Crypto Deep Profile") spec a verifier-review
work-packet emitter that runs under `make audit-deep WS=<ws> DEEP_PROFILE=crypto`.
This script is the implementation. It is intentionally Tier-B / advisory:

- It is NEVER added to the default `make audit` chain.
- It is invoked only when `DEEP_PROFILE=crypto` is set on `make audit-deep`.
- It NEVER fails the audit run on its own; the worst outcome is an empty
  packet and a report that says "no verifier candidates found".

V5-P0-09 / Gap 19: in-scope-surface auto-skip.
  Before scanning, the runner inspects the workspace's `src/` (or
  `contracts/`) tree for verifier-shaped substrings, deliberately ignoring
  ``lib/``, ``node_modules/``, ``test/``, and ``mock/`` paths. If zero
  in-scope verifier surface is detected, the runner emits a single
  SKIPPED line and exits 0 without producing the 161KB OPEN-noise report
  that previously fired on every non-verifier protocol. ``--force``
  bypasses the auto-skip when the operator explicitly wants the
  heuristic-only crypto sweep.

What it does (two phases in one script - stdlib only):

1. **Detect.** Walk `<root>` (the workspace's contracts dir, or `<root>` itself)
   for `.sol` files whose contract name or imports look like a verifier or
   proof system (Verifier, ZK, TEE, Plonk, Groth, Risc0, SP1, BLS, Aggregate,
   Snark, gnark, snarkjs, aztec, openzeppelin/utils/cryptography, ...). Emit a
   JSON work packet describing each candidate.

2. **Emit report.** Load `templates/crypto_verifier_review.md`, classify each
   candidate against the V4 status vocabulary (`OPEN`,
   `RULED_OUT_WITH_LINES`, `DEFENSE_IN_DEPTH_ONLY`, `OOS_DEPENDENT`,
   `NEEDS_SPECIALIST`) using a small heuristic, and replace the
   AUTO-GENERATED table marker in the template with a status-filled table.
   Write the result to `<workspace>/.audit_logs/crypto_deep_report.md`.

What it does NOT do (deliberate):

- It does NOT run any LLM. Kimi/Minimax dispatch happens through
  `tools/llm-dispatch.py` separately; the work packet is the hand-off.
- It does NOT prove soundness. Every `OPEN` row still requires human or
  Codex review.
- It does NOT add any new pip dependency. Stdlib only (re, json, argparse,
  pathlib).

Usage
-----

    python3 tools/crypto-deep-runner.py \\
        --root /path/to/contracts \\
        --template templates/crypto_verifier_review.md \\
        --packet-out .audit_logs/crypto_work_packet.json \\
        --report-out .audit_logs/crypto_deep_report.md

Or split-phase:

    python3 tools/crypto-deep-runner.py --phase detect ...
    python3 tools/crypto-deep-runner.py --phase emit   ...

Exit codes:
  0 - normal (even when zero candidates were found)
  2 - argument or filesystem error
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Optional


# --- detection patterns -----------------------------------------------------

# Contract-name regexes that strongly suggest a verifier or proof system.
# Conservative on purpose: false positives here just mean an extra row in the
# report, not a broken audit.
_VERIFIER_NAME_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bcontract\s+(\w*Verifier\w*)\b"),
    re.compile(r"\bcontract\s+(ZK\w+)\b"),
    re.compile(r"\bcontract\s+(TEE\w+)\b"),
    re.compile(r"\bcontract\s+(Plonk\w*)\b"),
    re.compile(r"\bcontract\s+(Groth\w*)\b"),
    re.compile(r"\bcontract\s+(Risc0\w*)\b"),
    re.compile(r"\bcontract\s+(SP1\w*)\b"),
    re.compile(r"\bcontract\s+(BLS\w*)\b"),
    re.compile(r"\bcontract\s+(Aggregate\w*)\b"),
    re.compile(r"\bcontract\s+(Snark\w*)\b"),
)

# Import paths that strongly suggest a proof / crypto dependency. Used both
# to flag detection and to power the OOS_DEPENDENT classification.
_PROOF_LIB_TOKENS: tuple[str, ...] = (
    "gnark",
    "snarkjs",
    "@aztec",
    "@matterlabs",
    "risc0",
    "sp1",
    "@openzeppelin/contracts/utils/cryptography",
)

_IMPORT_LINE_RE = re.compile(r"""\bimport\s+[^"';]*["']([^"']+)["']""")


# Heuristic markers for "this section is at least addressed somewhere". The
# classifier uses these to decide between OPEN and DEFENSE_IN_DEPTH_ONLY.
# Important: missing => OPEN (fail-safe). Presence is necessary but not
# sufficient for RULED_OUT_WITH_LINES, which still requires human sign-off.
_HEURISTIC_MARKERS: dict[str, tuple[str, ...]] = {
    "domain_separator": ("DOMAIN_SEPARATOR", "EIP712Domain", "domainSeparator"),
    "chain_id": ("block.chainid", "CHAIN_ID", "chainId"),
    "vk_binding": ("verifyingKey", "vkHash", "imageId", "VK_HASH"),
    "transcript": ("transcript", "challenge", "fiatShamir"),
    "replay": ("nonce", "usedProof", "deadline", "expiry"),
    "duplicate": ("duplicate", "alreadyUsed", "sortedSigners", "dedup"),
    "decoding_revert": ("revert", "require(", "InvalidProof"),
    "init_auth": ("onlyOwner", "AccessControl", "initializer", "onlyRole"),
    "soundness_bounds": ("require(", "bound", "isOnCurve", "validate"),
}


# Section names from templates/crypto_verifier_review.md, in canonical order.
# Keep in sync with the template's headings.
_SECTIONS: tuple[str, ...] = (
    "Assets Reviewed",
    "Proof Objects",
    "Public Inputs",
    "Domain Separation",
    "Chain-ID Binding",
    "VK Binding",
    "Transcript Binding",
    "Replay Prevention",
    "Threshold / Quorum",
    "Duplicate Proof / Signer",
    "Malformed Proof Decoding",
    "Init / Auth",
    "Soundness Alerts",
    "Trusted Setup",
    "Out-of-Scope Dependencies",
    "Findings Ruled Out",
    "Residual Observations",
)


# Status vocabulary - must match the V4 Workstream C2 spec EXACTLY.
STATUS_OPEN = "OPEN"
STATUS_RULED_OUT = "RULED_OUT_WITH_LINES"
STATUS_DEFENSE_IN_DEPTH = "DEFENSE_IN_DEPTH_ONLY"
STATUS_OOS = "OOS_DEPENDENT"
STATUS_NEEDS_SPECIALIST = "NEEDS_SPECIALIST"


# --- detection phase --------------------------------------------------------


def _iter_sol_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return []
    return sorted(p for p in root.rglob("*.sol") if p.is_file())


# V5-P0-09 / Gap 19: in-scope-surface preflight.
#
# Substrings that strongly suggest the workspace has a real verifier surface
# the protocol is responsible for. Substring match (not regex) by design — we
# want this preflight to be cheap, deterministic, and easy to audit by eye.
# Coverage matches Codex's plan: verify(, verifyProof(, IVerifier,
# Verifier.sol, Plonk, Groth, Risc0, SP1, Aggregate, Snark.
#
# We additionally treat proof-library imports as surface so the existing
# OOS_DEPENDENT classification path still triggers (a workspace that
# imports gnark/snarkjs/risc0/etc. but has no in-repo verifier contract
# is precisely the case the V4 P3 OOS_DEPENDENT row is for).
_SURFACE_TOKENS: tuple[str, ...] = (
    "verify(",
    "verifyProof(",
    "IVerifier",
    "Verifier.sol",
    "Plonk",
    "Groth",
    "Risc0",
    "SP1",
    "Aggregate",
    "Snark",
    # Proof-library import substrings — keep in sync with _PROOF_LIB_TOKENS.
    "gnark",
    "snarkjs",
    "@aztec",
    "@matterlabs",
    "risc0",
    "sp1",
    "@openzeppelin/contracts/utils/cryptography",
)

# Path components we deliberately skip when looking for in-scope verifier
# surface. Vendored libraries, node modules, tests, and mocks are common
# sources of false positives — Codex's plan: "must not treat vendored
# library verifier names as a target surface unless explicitly requested".
_SURFACE_SKIP_DIRS: tuple[str, ...] = (
    "lib",
    "node_modules",
    "test",
    "tests",
    "mock",
    "mocks",
)


def _has_inscope_verifier_surface(workspace: Path) -> tuple[bool, dict]:
    """Return (has_surface, evidence).

    Walks the workspace's `src/` (preferred) or `contracts/` (fallback)
    tree, skipping vendored / test / mock directories, and returns True
    on the FIRST in-scope file whose contents contain any token from
    `_SURFACE_TOKENS`. Evidence is a dict of {token: <relative path>} for
    the first hit per token; useful for the SKIPPED message and tests.

    The walk is bounded (we read up to 256KB per file). The returned
    evidence is a small dict, never the file contents.
    """
    evidence: dict[str, str] = {}
    candidate_roots = []
    if (workspace / "src").is_dir():
        candidate_roots.append(workspace / "src")
    if (workspace / "contracts").is_dir():
        candidate_roots.append(workspace / "contracts")
    if not candidate_roots:
        # Fall back to the workspace itself but still apply skip-dirs;
        # the test fixtures depend on this so a workspace with only a
        # verifier file at the root still detects.
        candidate_roots.append(workspace)

    for root in candidate_roots:
        if not root.exists():
            continue
        for f in sorted(root.rglob("*.sol")):
            try:
                rel_parts = f.relative_to(workspace).parts
            except ValueError:
                rel_parts = f.parts
            # Skip if any path part matches a vendored/test/mock dir.
            if any(part in _SURFACE_SKIP_DIRS for part in rel_parts):
                continue
            try:
                src = f.read_text(encoding="utf-8", errors="replace")[:262144]
            except OSError:
                continue
            # Path-based substrings (e.g., "Verifier.sol") match the file
            # name itself; content tokens match the source.
            haystack = str(f.name) + "\n" + src
            for tok in _SURFACE_TOKENS:
                if tok in haystack and tok not in evidence:
                    try:
                        rel = str(f.relative_to(workspace))
                    except ValueError:
                        rel = str(f)
                    evidence[tok] = rel
            if evidence:
                # We have at least one hit — return early; this preflight
                # only needs to answer yes/no.
                return True, evidence
    return bool(evidence), evidence


def _extract_contracts(text: str) -> list[str]:
    hits: list[str] = []
    for rx in _VERIFIER_NAME_RES:
        hits.extend(rx.findall(text))
    # Preserve order, drop duplicates.
    seen: set[str] = set()
    ordered: list[str] = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            ordered.append(h)
    return ordered


def _extract_imports(text: str) -> list[str]:
    return _IMPORT_LINE_RE.findall(text)


def _has_proof_import(imports: list[str]) -> bool:
    for imp in imports:
        for tok in _PROOF_LIB_TOKENS:
            if tok in imp:
                return True
    return False


def _markers_present(text: str) -> dict[str, bool]:
    return {
        name: any(tok in text for tok in toks)
        for name, toks in _HEURISTIC_MARKERS.items()
    }


def detect(root: Path) -> dict:
    """Walk ``root`` and return the work packet dict.

    The packet shape is the schema test_work_packet_schema enforces. Treat it
    as load-bearing - downstream LLM dispatch and the report emitter both
    depend on these keys.
    """
    candidates: list[dict] = []
    files_scanned = 0
    for f in _iter_sol_files(root):
        files_scanned += 1
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        contracts = _extract_contracts(src)
        imports = _extract_imports(src)
        proof_import = _has_proof_import(imports)
        if not contracts and not proof_import:
            continue
        candidates.append({
            "file": str(f),
            "contracts": contracts,
            "imports": imports,
            "has_proof_import": proof_import,
            "markers": _markers_present(src),
        })
    return {
        "schema_version": 1,
        "root": str(root),
        "files_scanned": files_scanned,
        "verifier_contracts": candidates,
    }


# --- classification ---------------------------------------------------------


# Map each section to a marker key (or None for sections that always require
# human review e.g. "Findings Ruled Out").
_SECTION_TO_MARKER: dict[str, str | None] = {
    "Assets Reviewed": None,
    "Proof Objects": None,
    "Public Inputs": None,
    "Domain Separation": "domain_separator",
    "Chain-ID Binding": "chain_id",
    "VK Binding": "vk_binding",
    "Transcript Binding": "transcript",
    "Replay Prevention": "replay",
    "Threshold / Quorum": None,
    "Duplicate Proof / Signer": "duplicate",
    "Malformed Proof Decoding": "decoding_revert",
    "Init / Auth": "init_auth",
    "Soundness Alerts": "soundness_bounds",
    "Trusted Setup": None,
    "Out-of-Scope Dependencies": None,
    "Findings Ruled Out": None,
    "Residual Observations": None,
}


def classify_section(section: str, item: dict) -> str:
    """Return one status token for (section, candidate) pair.

    Decision rules (deliberately conservative):

    1. If the candidate's only signal is a proof-library import (no in-repo
       verifier contract), classify as ``OOS_DEPENDENT``.
    2. If a contract name strongly matches a known proof framework
       (Plonk/Groth/Risc0/SP1/Aggregate/Snark), the section is at best
       ``DEFENSE_IN_DEPTH_ONLY`` because the heavy lifting is in the
       framework, not the on-chain wrapper.
    3. For sections that map to a heuristic marker (domain_separator,
       chain_id, vk_binding, ...): if the marker is present in the file,
       fall through to ``DEFENSE_IN_DEPTH_ONLY``; if absent, ``OPEN``.
    4. Sections without a marker default to ``OPEN`` so they show up in the
       review queue.
    5. The runner NEVER emits ``RULED_OUT_WITH_LINES`` or
       ``NEEDS_SPECIALIST`` on its own. Those are reserved for human review;
       this script's output is always the starting point, never the verdict.
    """
    contracts = item.get("contracts") or []
    has_proof_import = bool(item.get("has_proof_import"))
    markers = item.get("markers") or {}

    if has_proof_import and not contracts:
        return STATUS_OOS

    is_framework = any(
        any(tag in c for tag in ("Plonk", "Groth", "Risc0", "SP1", "Aggregate", "Snark"))
        for c in contracts
    )

    marker_key = _SECTION_TO_MARKER.get(section)
    if marker_key is not None:
        if markers.get(marker_key):
            return STATUS_DEFENSE_IN_DEPTH if is_framework else STATUS_DEFENSE_IN_DEPTH
        return STATUS_OPEN
    # Marker-less sections always start OPEN; framework wrappers only earn
    # DEFENSE_IN_DEPTH_ONLY when there's a positive marker, which by
    # definition there isn't here.
    return STATUS_OPEN


# --- report emit phase ------------------------------------------------------


_AUTO_TABLE_MARKER = "<!-- AUTO-GENERATED TABLE (filled by report-emitter) -->"

_PLACEHOLDER_TABLE_RE = re.compile(
    r"\| Section \| Status \| Evidence \|\n\|---------\|--------\|----------\|\n\| 1-17 \| \.\.\. \| \.\.\. \|\n?",
)


def _table_for_packet(packet: dict) -> str:
    items = packet.get("verifier_contracts") or []
    if not items:
        # No candidates - emit a single sentinel row so the report still
        # renders cleanly and the operator sees the empty result explicitly.
        rows = ["| (no candidates) | OPEN | no verifier-shaped contracts detected under root |"]
    else:
        rows = []
        for sec in _SECTIONS:
            for it in items:
                status = classify_section(sec, it)
                evidence = it.get("file", "")
                rows.append(f"| {sec} | {status} | {evidence} |")
    header = "| Section | Status | Evidence |\n|---------|--------|----------|\n"
    return header + "\n".join(rows) + "\n"


def emit_report(packet_path: Path, template_path: Path, out_path: Path) -> None:
    if not packet_path.exists():
        raise FileNotFoundError(f"work packet not found: {packet_path}")
    if not template_path.exists():
        raise FileNotFoundError(f"template not found: {template_path}")
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    template = template_path.read_text(encoding="utf-8")
    table = _table_for_packet(packet)

    # Replace the AUTO-GENERATED MARKER and the placeholder table that
    # follows it in the template. We do BOTH so the template stays
    # human-readable (renders as-is in GitHub) AND the emitted report has a
    # filled table.
    if _AUTO_TABLE_MARKER in template:
        template = template.replace(_AUTO_TABLE_MARKER, table, 1)
    template = _PLACEHOLDER_TABLE_RE.sub("", template)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(template, encoding="utf-8")


# --- driver -----------------------------------------------------------------


# --- V5 deep-candidate emission (opt-in) ------------------------------------


def _load_deep_candidate_lib() -> Optional[Any]:
    spec_path = Path(__file__).resolve().parent / "lib" / "deep_candidate.py"
    if not spec_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_deep_candidate_lib_crypto", spec_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_deep_candidate_lib_crypto", module)
    spec.loader.exec_module(module)
    return module


def _emit_crypto_candidates(workspace: Path, packet: dict) -> int:
    """Emit one deep_candidate.v1 doc per detected verifier surface.

    Each candidate carries ``confidence='low'`` + non-empty ``blocking_questions``
    because crypto detection alone does NOT prove a verifier is exploitable;
    the candidate is a hand-off for specialist review (Workstream C).
    """
    lib = _load_deep_candidate_lib()
    if lib is None:
        return 0
    verifiers = packet.get("verifier_contracts") or []
    if not verifiers:
        return 0
    count = 0
    for entry in verifiers:
        contracts = entry.get("contracts") or []
        contract_label = "_".join(c[:32] for c in contracts) or "unknown"
        file_path = entry.get("file") or ""
        markers = entry.get("markers") or {}
        missing = [k for k, v in markers.items() if not v]
        doc = lib.build_candidate(
            lane="crypto",
            candidate_id=f"crypto.verifier.{contract_label}",
            files=[file_path] if file_path else ["unknown.sol"],
            claim=(
                "Verifier-shaped contract detected; specialist review required "
                f"for proof binding ({', '.join(contracts) if contracts else 'unnamed'})."
            ),
            trigger=(
                "Caller submits a proof / aggregated signature to the detected "
                "verifier surface. Heuristic markers found: "
                f"{sorted(k for k, v in markers.items() if v) or ['none']}."
            ),
            impact=(
                "Until specialist review confirms domain/chain/VK/transcript "
                "binding and replay prevention, the contract MAY accept "
                "malformed or replayed proofs. This emission is advisory."
            ),
            reproduction=(
                "Run templates/crypto_verifier_review.md against "
                f"{file_path}; collect line-anchored evidence for each section "
                "before promoting to a finding."
            ),
            blocking_questions=(
                [
                    "Which proof system is in use (Groth16 / Plonk / Risc0 / SP1 / BLS / SNARK)?",
                    "Is the verifying-key bound on-chain or fetched from a config?",
                    "Does the verifier check chain-id + domain separator?",
                ]
                + (
                    [f"Missing heuristic marker(s): {', '.join(missing)}"]
                    if missing
                    else []
                )
            ),
            tool="crypto-deep-runner.py",
            workspace=workspace,
            lane_payload={
                "verifier": entry,
                "missing_markers": missing,
            },
        )
        lib.write_candidate(doc, workspace=workspace)
        count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="V4 P3 crypto deep-profile runner (Tier-B advisory).",
    )
    p.add_argument("--phase", choices=("detect", "emit", "all"), default="all",
                   help="Run only the detect phase, only the emit phase, or both (default).")
    p.add_argument("--root", type=Path, default=None,
                   help="Project root to scan for verifier-shaped contracts.")
    p.add_argument("--template", type=Path, default=None,
                   help="Path to templates/crypto_verifier_review.md.")
    p.add_argument("--packet-out", type=Path, default=None,
                   help="Where to write the JSON work packet.")
    p.add_argument("--report-out", type=Path, default=None,
                   help="Where to write the Markdown deep report.")
    p.add_argument("--force", action="store_true",
                   help="Bypass the V5-P0-09 in-scope-surface preflight and "
                        "always run detect+emit, even when no verifier "
                        "surface is detected. Use only when the operator "
                        "has explicitly requested a heuristic-only sweep.")
    p.add_argument("--workspace", type=Path, default=None,
                   help="Workspace directory used for the in-scope-surface "
                        "preflight. Defaults to --root's parent when --root "
                        "looks like <ws>/src or <ws>/contracts.")
    p.add_argument("--emit-candidate", action="store_true",
                   help="Opt-in: write deep_candidate.v1 JSON files to "
                        "<workspace>/deep_candidates/ for each detected "
                        "verifier surface. Default outputs unchanged. "
                        "Acceptance test 2: when no surface is detected the "
                        "skip path runs FIRST (no empty-candidate green-light).")
    args = p.parse_args(argv)

    # V5-P0-09 / Gap 19: in-scope-surface preflight.
    #
    # If the workspace has no in-scope verifier surface, emit a single
    # SKIPPED line and exit 0 without producing the OPEN-noise report. The
    # preflight only fires when --root is supplied (i.e. detect or all
    # phases); a pure --phase emit invocation is left alone because the
    # caller already has a packet and is asking for a report only.
    if args.phase in ("detect", "all") and not args.force and args.root is not None:
        # Default workspace = --root's parent if root is named src/ or
        # contracts/, otherwise --root itself.
        ws = args.workspace
        if ws is None:
            try:
                root_path = args.root.resolve()
                if root_path.name in ("src", "contracts"):
                    ws = root_path.parent
                else:
                    ws = root_path
            except OSError:
                ws = args.root
        try:
            has_surface, evidence = _has_inscope_verifier_surface(ws)
        except OSError as exc:
            # Fail open — if we can't inspect the workspace, fall through
            # to the existing detect path so we don't accidentally hide a
            # real failure behind the preflight.
            has_surface, evidence = True, {"_error": f"surface preflight: {exc}"}
        if not has_surface:
            print(
                "crypto-deep: SKIPPED — no verifier surface in workspace",
                file=sys.stderr,
            )
            # Emit a tiny report so downstream automation
            # (audit-deep.sh's Outputs section) doesn't choke on a missing
            # file. The skipped report is intentionally short — no 161KB
            # OPEN-noise.
            if args.report_out is not None:
                try:
                    args.report_out.parent.mkdir(parents=True, exist_ok=True)
                    args.report_out.write_text(
                        "# crypto-deep — SKIPPED\n\n"
                        "No verifier surface detected in workspace `"
                        f"{ws}`.\n\n"
                        "Heuristic looked for these tokens in `src/` or "
                        "`contracts/` (skipping `lib/`, `node_modules/`, "
                        "`test/`, `mock/`):\n\n"
                        + "\n".join(f"- `{t}`" for t in _SURFACE_TOKENS)
                        + "\n\nUse `--force` to override this preflight.\n",
                        encoding="utf-8",
                    )
                except OSError:
                    pass
            if args.packet_out is not None:
                try:
                    args.packet_out.parent.mkdir(parents=True, exist_ok=True)
                    args.packet_out.write_text(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "root": str(args.root),
                                "files_scanned": 0,
                                "verifier_contracts": [],
                                "skipped": True,
                                "skip_reason": "no_inscope_verifier_surface",
                                "workspace": str(ws),
                            },
                            indent=2,
                        ),
                        encoding="utf-8",
                    )
                except OSError:
                    pass
            return 0

    try:
        if args.phase in ("detect", "all"):
            if args.root is None or args.packet_out is None:
                print("[crypto-deep] error: --root and --packet-out are required for detect phase",
                      file=sys.stderr)
                return 2
            packet = detect(args.root)
            args.packet_out.parent.mkdir(parents=True, exist_ok=True)
            args.packet_out.write_text(json.dumps(packet, indent=2),
                                       encoding="utf-8")
            print(f"[crypto-deep] detect: scanned {packet['files_scanned']} .sol files, "
                  f"{len(packet['verifier_contracts'])} candidate(s) -> {args.packet_out}",
                  file=sys.stderr)
            if args.emit_candidate:
                # Workspace defaulting matches the --force preflight branch.
                ws_for_emit = args.workspace
                if ws_for_emit is None:
                    try:
                        rp = args.root.resolve()
                        ws_for_emit = rp.parent if rp.name in ("src", "contracts") else rp
                    except OSError:
                        ws_for_emit = args.root
                emitted = _emit_crypto_candidates(ws_for_emit, packet)
                # Acceptance test 2: zero verifier_contracts MUST NOT produce a
                # green-with-empty-candidate; we route through the same
                # skip-style print and write nothing.
                if emitted == 0:
                    print(
                        "[crypto-deep] EMIT skipped: no verifier surface to emit "
                        "(zero verifier_contracts in packet)",
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"[crypto-deep] EMIT deep_candidates={emitted} "
                        f"dir={ws_for_emit / 'deep_candidates'}",
                        file=sys.stderr,
                    )
        if args.phase in ("emit", "all"):
            if args.template is None or args.packet_out is None or args.report_out is None:
                print("[crypto-deep] error: --template, --packet-out, --report-out are required for emit phase",
                      file=sys.stderr)
                return 2
            emit_report(args.packet_out, args.template, args.report_out)
            print(f"[crypto-deep] emit: report -> {args.report_out}", file=sys.stderr)
    except FileNotFoundError as exc:
        print(f"[crypto-deep] error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
