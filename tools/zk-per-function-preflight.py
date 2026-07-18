#!/usr/bin/env python3
"""zk-per-function-preflight.py - verifier-function-shaped pre-flight packs.

RELATED TOOLS:
  - tools/per-function-preflight-orchestrator.py : the Solidity-function-shaped
    analog. It parses ordinary Solidity functions and builds packs from
    vault_function_signature_shape / vault_per_function_hunter_brief etc. It is
    NOT verifier-aware (no transcript / Fiat-Shamir / sumcheck step invariants,
    no zkBugs corpus lookup). This tool is its ZK verifier analog.
  - tools/zk-verifier-bugclass-checklist.py : Stage 2 of `make zk-hunt`. Emits
    a flat zk_hunt_queue.jsonl of (fn x bug_class) predicates across the whole
    workspace. This tool REUSES that tool's verifier-file discovery,
    BUG_CLASS_PREDICATES, and fn->bug-class mapping, but reshapes the output
    per-FUNCTION (one pack per verifier function) and adds (a) per-step
    invariants, (b) composable zk chain candidates, and (c) the prior-finding
    lookup via vault_zk_template_lookup.
  - tools/zk-function-mindset.py : circuit-side (circom/halo2) per-template
    sibling. Looks at prover witness logic, not the on-chain verifier.

Gap filled: a per-VERIFIER-FUNCTION pre-flight pack that mirrors the Solidity
per-function-preflight pack shape but is ZK-verifier-shaped:
  (a) per-step invariants - what MUST hold for that function's soundness:
      all Fiat-Shamir challenges transcript-derived, all field ops constrained,
      transcript-absorb completeness, sumcheck round-count binding, etc.
  (b) zk chain candidates - which soundness gaps in this function could COMPOSE
      with gaps in sibling verifier functions to reach a forged-proof impact.
  (c) bug-class checklist hits - the BUG_CLASS_PREDICATES rows that match this
      function (from zk-verifier-bugclass-checklist.py).
Plus prior zkBugs corpus findings via vault_zk_template_lookup keyed on the
verifier function name (the zkBugs corpus uses the verifier fn name as
template_name, e.g. verifySumcheck / verifyShplemini).

CLI:
    python3 tools/zk-per-function-preflight.py --workspace <ws> \\
        [--honk-dir <dir>] [--output-dir <dir>] [--mcp-timeout N] \\
        [--no-mcp] [--dry-run] [--json]

Output:
    <ws>/.auditooor/zk_preflight_packs/zk_preflight_pack_<Contract>_<fn>.json
    <ws>/.auditooor/zk_preflight_packs/manifest.json

Exit codes:
    0  packs written (>=0 functions; 0 is valid for an empty surface)
    1  no verifier surface found
    2  argument error
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
PACK_SCHEMA = "auditooor.zk_pre_flight_pack.v1"
MANIFEST_SCHEMA = "auditooor.zk_pre_flight_pack_manifest.v1"


# --------------------------------------------------------------------------
# Reuse the bug-class-checklist module (discovery + predicates + fn mapping).
# --------------------------------------------------------------------------
def _load_bugclass_module():
    path = ROOT / "tools" / "zk-verifier-bugclass-checklist.py"
    spec = importlib.util.spec_from_file_location("zk_vbc_reuse", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------
# Per-step invariant library. Each entry says, for a verifier-function role,
# what MUST hold for the soundness of that step. These are the "what MUST be
# true" obligations the worker should confirm in source before clearing the
# function. They are keyed by token that appears in the fn name or body.
# --------------------------------------------------------------------------
STEP_INVARIANTS: list[dict[str, Any]] = [
    {
        "invariant_id": "ZK-INV-TRANSCRIPT-COMPLETE",
        "match_keywords": ["transcript", "absorb", "squeeze", "getchallenge",
                            "squeezechallenge", "transcriptinit"],
        "must_hold": (
            "Every public input, the verification-key hash, and every prior "
            "round commitment is absorbed into the transcript BEFORE any "
            "challenge is squeezed. No challenge may be drawn from an "
            "incomplete transcript."
        ),
        "violation_impact": (
            "A prover substitutes a different vk or public-input vector that "
            "the challenge never committed to - soundness break, forged proof."
        ),
        "related_bug_class": "transcript-absorb-completeness",
    },
    {
        "invariant_id": "ZK-INV-FS-DERIVED-CHALLENGES",
        "match_keywords": ["challenge", "getchallenge", "splitchallenge",
                            "squeezechallenge", "eta", "beta", "gamma"],
        "must_hold": (
            "Every challenge used in this function is derived from the "
            "Fiat-Shamir transcript (not a free/calldata-supplied value) and "
            "each FS domain uses a unique, non-reused label."
        ),
        "violation_impact": (
            "A free or domain-colliding challenge lets the prover pick a "
            "convenient value, defeating the random-oracle soundness argument."
        ),
        "related_bug_class": "fs-challenge-domain-separation",
    },
    {
        "invariant_id": "ZK-INV-FIELD-OPS-CONSTRAINED",
        "match_keywords": ["invert", "modinverse", "inverse", "divmod",
                            "fr.wrap", "batchinvert"],
        "must_hold": (
            "Every field operation is constrained: every modular-inverse "
            "input is checked != 0 before inversion, and every Fr value used "
            "in an accumulation is reduced mod p."
        ),
        "violation_impact": (
            "Division-by-zero in the field returns 0 or reverts; either path "
            "is a soundness or liveness break depending on the call site."
        ),
        "related_bug_class": "field-inversion-zero-check",
    },
    {
        "invariant_id": "ZK-INV-CURVE-MEMBERSHIP",
        "match_keywords": ["batchmul", "batchverify", "pairing", "staticcall",
                            "ecadd", "ecmul", "g1point", "g2point"],
        "must_hold": (
            "Every proof-element curve point is membership-checked AND "
            "point-at-infinity-rejected BEFORE it enters any accumulation, "
            "not only at the final pairing."
        ),
        "violation_impact": (
            "A single unchecked point (e.g. point at infinity) injected into "
            "the accumulator breaks the soundness of the whole batch."
        ),
        "related_bug_class": "curve-membership-check",
    },
    {
        "invariant_id": "ZK-INV-PUBLIC-INPUT-BINDING",
        "match_keywords": ["publicinputdelta", "computepublicinputdelta",
                            "verify", "verifyproof", "publicinputs"],
        "must_hold": (
            "Public inputs are bound into the Fiat-Shamir transcript BEFORE "
            "the first challenge is emitted, so every challenge depends on the "
            "public inputs."
        ),
        "violation_impact": (
            "Late (post-hoc) public-input absorption makes the challenges "
            "independent of the public inputs - the proof no longer binds the "
            "claimed statement."
        ),
        "related_bug_class": "public-input-delta-fiat-shamir-binding",
    },
    {
        "invariant_id": "ZK-INV-SUMCHECK-ROUND-COUNT",
        "match_keywords": ["verifysumcheck", "sumcheck", "sumcheckround",
                            "logn", "numrounds", "computenexttargetsum",
                            "checksum", "partiallyevaluatepow"],
        "must_hold": (
            "The number of sumcheck rounds is asserted == log2(circuit_size) "
            "and each round's target-sum equality (checkSum) is enforced; the "
            "round loop bound is CONST_PROOF_SIZE_LOG_N."
        ),
        "violation_impact": (
            "A prover that can short the round count skips polynomial "
            "relations, forging proofs for under-constrained circuits."
        ),
        "related_bug_class": "sumcheck-round-count-enforcement",
    },
    {
        "invariant_id": "ZK-INV-OPENING-PROOF-BINDING",
        "match_keywords": ["verifyshplemini", "verifyopeningproof", "kzg",
                            "shplemini", "evaluation_challenge", "batchmul"],
        "must_hold": (
            "The evaluation point r is squeezed from the transcript BEFORE "
            "the opening polynomial / opening query is constructed; the "
            "opening proof binds the committed polynomials at that r."
        ),
        "violation_impact": (
            "A free evaluation point r lets the prover choose a convenient "
            "point, breaking the opening-proof binding (Shplemini/KZG)."
        ),
        "related_bug_class": "shplemini-opening-proof-binding",
    },
    {
        "invariant_id": "ZK-INV-AGGREGATION-PARITY",
        "match_keywords": ["verifyzkproof", "verifyrecursive", "verifyaggregation",
                            "basezkhonkverifier", "basehonkverifier", "aggregation"],
        "must_hold": (
            "The ZK and non-ZK verifier paths process the aggregation object / "
            "pairing accumulator symmetrically; any aggregation step present in "
            "one path but absent in the other is intentional and documented."
        ),
        "violation_impact": (
            "Asymmetric aggregation handling creates a soundness bypass on the "
            "path that skips the accumulator (IPA / pairing) processing."
        ),
        "related_bug_class": "recursion-aggregation-object-skip",
    },
]


# --------------------------------------------------------------------------
# zk chain candidate edges. Each edge is a "if this function's step is weak,
# it can compose with a sibling function's weak step to reach impact X". The
# composition is keyed on bug-class pairs that historically chain into a
# forged-proof / accepted-invalid-proof impact.
# --------------------------------------------------------------------------
CHAIN_EDGES: list[dict[str, Any]] = [
    {
        "from_bug_class": "transcript-absorb-completeness",
        "to_bug_class": "public-input-delta-fiat-shamir-binding",
        "composed_impact": (
            "Incomplete transcript absorption + unbound public-input delta lets "
            "a prover swap public inputs after the challenge is fixed -> "
            "accepted-invalid-proof for an arbitrary statement."
        ),
        "severity_hint": "CRITICAL",
    },
    {
        "from_bug_class": "fs-challenge-domain-separation",
        "to_bug_class": "shplemini-opening-proof-binding",
        "composed_impact": (
            "Colliding FS challenge domains + a free evaluation point r lets a "
            "prover reuse a challenge across the sumcheck and opening domains "
            "-> opening-proof forgery."
        ),
        "severity_hint": "HIGH",
    },
    {
        "from_bug_class": "curve-membership-check",
        "to_bug_class": "shplemini-opening-proof-binding",
        "composed_impact": (
            "An unchecked point injected into batchMul accumulation + a weakly "
            "bound opening proof composes into an accepted batch with a forged "
            "commitment -> forged proof."
        ),
        "severity_hint": "HIGH",
    },
    {
        "from_bug_class": "sumcheck-round-count-enforcement",
        "to_bug_class": "shplemini-opening-proof-binding",
        "composed_impact": (
            "A shortened sumcheck round count + a free opening point lets a "
            "prover skip relations and then open at a point that hides the "
            "skip -> false proof for an under-constrained circuit."
        ),
        "severity_hint": "HIGH",
    },
    {
        "from_bug_class": "field-inversion-zero-check",
        "to_bug_class": "curve-membership-check",
        "composed_impact": (
            "A zero-inverse producing a degenerate scalar + an unchecked curve "
            "point lets a prover steer the accumulation to a point that passes "
            "the final pairing -> soundness break."
        ),
        "severity_hint": "HIGH",
    },
    {
        "from_bug_class": "recursion-aggregation-object-skip",
        "to_bug_class": "transcript-absorb-completeness",
        "composed_impact": (
            "A skipped aggregation object on the non-ZK path + incomplete "
            "transcript absorption lets a recursive proof carry an unverified "
            "accumulator -> forged recursive proof."
        ),
        "severity_hint": "CRITICAL",
    },
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("_", "-") else "_" for ch in value)


def discover_verifier_files(workspace: Path, honk_dir: Path | None, bvc) -> list[Path]:
    """Discover verifier .sol files. If honk_dir is given, scan it directly;
    else fall back to the bug-class checklist's workspace-wide discovery."""
    if honk_dir is not None:
        files: list[Path] = []
        for p in sorted(honk_dir.rglob("*.sol")):
            if any(part in {".git", "node_modules", "build", "dist", "__pycache__"}
                   for part in p.parts):
                continue
            try:
                if p.stat().st_size > 2 * 1024 * 1024:
                    continue
            except OSError:
                continue
            if bvc._is_verifier_file(p):
                files.append(p)
        return files
    return [f for f in bvc._find_sol_files(workspace) if bvc._is_verifier_file(f)]


def _extract_function_with_lines(text: str) -> list[dict[str, Any]]:
    """Return [{fn, line, body}] for each top-level function in the file.
    Body is brace-matched; for declaration-only (virtual) functions the body
    is the signature line."""
    out: list[dict[str, Any]] = []
    fn_pat = re.compile(r"\bfunction\s+(\w+)\s*\(")
    for m in fn_pat.finditer(text):
        fn_name = m.group(1)
        start = m.start()
        line_no = text.count("\n", 0, start) + 1
        # Find body via brace matching from the first { after the signature,
        # but stop if a ; appears first (declaration-only).
        brace_idx = text.find("{", m.end())
        semi_idx = text.find(";", m.end())
        if brace_idx == -1 or (semi_idx != -1 and semi_idx < brace_idx):
            # declaration-only function (interface / virtual)
            end = semi_idx if semi_idx != -1 else m.end()
            body = text[start:end + 1]
        else:
            depth = 0
            end = brace_idx
            for idx in range(brace_idx, len(text)):
                ch = text[idx]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = idx + 1
                        break
            body = text[start:end]
        out.append({"fn": fn_name, "line": line_no, "body": body})
    return out


def call_zk_template_lookup(template_name: str, framework: str, timeout: int) -> dict[str, Any]:
    """Invoke vault_zk_template_lookup via the MCP server CLI. Returns the
    parsed payload, or a status block on failure."""
    args = json.dumps({"framework": framework, "template_name": template_name, "limit": 5})
    cmd = [
        sys.executable,
        str(ROOT / "tools" / "vault-mcp-server.py"),
        "--call", "vault_zk_template_lookup",
        "--args", args,
    ]
    try:
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "skipped", "reason": "mcp_timeout"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc)}
    if proc.returncode != 0:
        return {"status": "skipped", "returncode": proc.returncode, "stderr_tail": proc.stderr[-500:]}
    payload_lines: list[str] = []
    in_json = False
    for line in proc.stdout.splitlines():
        if line.startswith("{"):
            in_json = True
        if in_json:
            payload_lines.append(line)
    blob = "\n".join(payload_lines)
    try:
        payload = json.loads(blob)
    except json.JSONDecodeError:
        return {"status": "unparseable", "raw_tail": blob[-500:]}
    payload["status"] = "ok"
    return payload


def build_step_invariants(fn_name: str, body: str) -> list[dict[str, Any]]:
    fn_lower = fn_name.lower()
    body_lower = body.lower()
    matched: list[dict[str, Any]] = []
    for inv in STEP_INVARIANTS:
        if any(kw in fn_lower or kw in body_lower for kw in inv["match_keywords"]):
            matched.append({
                "invariant_id": inv["invariant_id"],
                "must_hold": inv["must_hold"],
                "violation_impact": inv["violation_impact"],
                "related_bug_class": inv["related_bug_class"],
            })
    return matched


def build_chain_candidates(bug_classes_in_fn: set[str]) -> list[dict[str, Any]]:
    """Return chain edges whose from_bug_class is present in this function.
    These are the gaps that, if this function is weak, could compose forward."""
    out: list[dict[str, Any]] = []
    for edge in CHAIN_EDGES:
        if edge["from_bug_class"] in bug_classes_in_fn:
            out.append(dict(edge))
    return out


def build_pack(
    fn_rec: dict[str, Any],
    sol_path: Path,
    text: str,
    bvc,
    framework: str,
    no_mcp: bool,
    timeout: int,
) -> dict[str, Any]:
    fn_name = fn_rec["fn"]
    line = fn_rec["line"]
    body = fn_rec["body"]
    file_line = f"{sol_path}:{line}"
    contract_name = sol_path.stem

    # (c) bug-class checklist hits (reuse the checklist's fn->class mapper,
    # but scope the text to this function body so the match is per-function).
    preds = bvc._map_fn_to_bug_classes(fn_name, body)
    bug_class_hits: list[dict[str, Any]] = []
    for pred in preds:
        bug_class_hits.append({
            "bug_class": pred["bug_class"],
            "question": pred["question"],
            "oracle_check": pred["oracle_check"],
            "severity_hint": pred["severity_hint"],
        })
    bug_classes_in_fn = {h["bug_class"] for h in bug_class_hits}

    # (a) per-step invariants
    step_invariants = build_step_invariants(fn_name, body)

    # (b) zk chain candidates
    chain_candidates = build_chain_candidates(bug_classes_in_fn)

    # prior-finding lookup keyed on the verifier fn name (zkBugs template_name)
    prior_lookup: dict[str, Any]
    if no_mcp:
        prior_lookup = {"status": "skipped", "reason": "--no-mcp"}
    else:
        prior_lookup = call_zk_template_lookup(fn_name, framework, timeout)

    return {
        "schema": PACK_SCHEMA,
        "generated_at": utc_now(),
        "framework": framework,
        "target": {
            "contract": contract_name,
            "function": fn_name,
            "source_ref": file_line,
        },
        "function_shape_local": {
            "source": "local-honk-verifier-parser",
            "contract_file": str(sol_path),
            "source_ref": file_line,
            "line": line,
            "function_name": fn_name,
            "body_bytes": len(body),
        },
        # (a)
        "step_invariants": step_invariants,
        # (b)
        "chain_candidates": chain_candidates,
        # (c)
        "bug_class_checklist_hits": bug_class_hits,
        "bug_classes": sorted(bug_classes_in_fn),
        # prior corpus
        "prior_finding_lookup": {
            "callable": "vault_zk_template_lookup",
            "template_name": fn_name,
            "status": prior_lookup.get("status", "unknown"),
            "total_found": prior_lookup.get("total_found", 0),
            "exemplars": prior_lookup.get("exemplars", []),
            "canonical_fixes": prior_lookup.get("canonical_fixes", []),
            "context_pack_id": prior_lookup.get("context_pack_id"),
            "context_pack_hash": prior_lookup.get("context_pack_hash"),
            "source_refs": prior_lookup.get("source_refs", []),
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True, help="Audit workspace root.")
    ap.add_argument("--honk-dir", help="Directory of honk verifier .sol files "
                    "(default: scan the whole workspace for verifier files).")
    ap.add_argument("--output-dir", help="Output dir "
                    "(default: <workspace>/.auditooor/zk_preflight_packs).")
    ap.add_argument("--framework", default="solidity-honk", help="Framework tag "
                    "for the prior-finding lookup (default: solidity-honk).")
    ap.add_argument("--mcp-timeout", type=int, default=20, help="Timeout per MCP call.")
    ap.add_argument("--no-mcp", action="store_true", help="Skip vault_zk_template_lookup.")
    ap.add_argument("--dry-run", action="store_true", help="Do not write pack files.")
    ap.add_argument("--json", action="store_true", help="Print manifest JSON to stdout.")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        sys.stderr.write(f"[zk-pfp] workspace not found: {workspace}\n")
        return 2
    honk_dir: Path | None = None
    if args.honk_dir:
        honk_dir = Path(args.honk_dir).expanduser().resolve()
        if not honk_dir.is_dir():
            sys.stderr.write(f"[zk-pfp] honk-dir not found: {honk_dir}\n")
            return 2

    bvc = _load_bugclass_module()
    sol_files = discover_verifier_files(workspace, honk_dir, bvc)
    if not sol_files:
        sys.stderr.write("[zk-pfp] no verifier .sol files found\n")
        if args.json:
            print(json.dumps({"schema": MANIFEST_SCHEMA, "pack_count": 0, "packs": []}))
        return 1

    output_dir = (Path(args.output_dir).expanduser().resolve()
                  if args.output_dir
                  else workspace / ".auditooor" / "zk_preflight_packs")
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    for sol_path in sol_files:
        try:
            text = sol_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for fn_rec in _extract_function_with_lines(text):
            pack = build_pack(fn_rec, sol_path, text, bvc, args.framework,
                              args.no_mcp, args.mcp_timeout)
            # Only emit a pack for functions that have at least one verifier
            # signal (a bug-class hit OR a step invariant). Pure getters with
            # no soundness obligation are skipped to keep packs focused.
            if not pack["bug_class_checklist_hits"] and not pack["step_invariants"]:
                continue
            filename = (f"zk_preflight_pack_{safe_slug(sol_path.stem)}_"
                        f"{safe_slug(fn_rec['fn'])}.json")
            path = output_dir / filename
            if not args.dry_run:
                path.write_text(json.dumps(pack, indent=2, sort_keys=True) + "\n",
                                encoding="utf-8")
            rows.append({
                "contract": sol_path.stem,
                "function": fn_rec["fn"],
                "source_ref": pack["target"]["source_ref"],
                "bug_classes": pack["bug_classes"],
                "step_invariant_count": len(pack["step_invariants"]),
                "chain_candidate_count": len(pack["chain_candidates"]),
                "prior_findings": pack["prior_finding_lookup"]["total_found"],
                "pack_path": str(path),
                "status": "would-write" if args.dry_run else "written",
            })

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "generated_at": utc_now(),
        "workspace": str(workspace),
        "honk_dir": str(honk_dir) if honk_dir else None,
        "framework": args.framework,
        "output_dir": str(output_dir),
        "verifier_file_count": len(sol_files),
        "pack_count": len(rows),
        "packs": rows,
    }
    if not args.dry_run:
        (output_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"[zk-pfp] verifier_files={len(sol_files)} packs={len(rows)} "
              f"output_dir={output_dir}")
        for row in rows[:10]:
            print(f"  {row['source_ref']:70s} {','.join(row['bug_classes']) or '-'}")
        if len(rows) > 10:
            print(f"  ... ({len(rows) - 10} more)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
