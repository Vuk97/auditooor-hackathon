#!/usr/bin/env python3
"""mining-manifest.py — durable per-campaign mining manifest writer.

Background
----------
V5 Gap-26 (V5-P0-18): the auditooor R38-R41 ``+65 patterns`` memory claim
was unverified because there was no per-campaign manifest mapping
``pattern_name -> source_packet -> provider -> verdict``. After-the-fact
grep over PR text was the only way to reconstruct what landed and why,
which made it impossible to cheaply audit "did this campaign actually
add the patterns it claimed?"

This tool writes a deterministic, schema-validated manifest at
``<workspace>/source_mining/<date>/mining_manifest.json`` once per source-
mining campaign run. It records the exact fields Codex specified:

  source_packet      path or hash of the truth packet sent to LLMs
  provider           kimi | minimax | both
  prompt_hash        SHA-256 of the dispatched prompt (reproducibility / dedup)
  context_size       tokens in the prompt (heuristic: ``len(text) // 4``)
  sampled_coverage   when only a subset of pattern names was shown,
                     {"shown": int, "total": int}
  candidate_count    raw candidates raised by LLM(s)
  rejection_count    M14-trap rejections
  promotion_count    candidates that became patterns
  workspace          workspace name (for cross-check by
                     ``library-source-coverage.py --audits-root``)
  campaign_date      YYYY-MM-DD
  campaign_label     free-form (e.g. ``oracle-pricing-domain``)

Schema validation (``--validate <path>``) accepts:
  - all required fields present
  - prompt_hash is a 64-char lowercase hex (SHA-256)
  - provider is one of {kimi, minimax, both}
  - candidate_count >= rejection_count + promotion_count (sanity)
  - context_size > 0
  - sampled_coverage.shown <= sampled_coverage.total when both present

Usage
-----
  # Write a manifest from JSON-encoded fields:
  python3 tools/mining-manifest.py write \\
      --workspace ~/audits/<ws> \\
      --date 2026-04-26 \\
      --provider both \\
      --source-packet ~/audits/<ws>/source_mining/2026-04-26/truth_packet.md \\
      --prompt-file <prompt.md> \\
      --candidate-count 17 \\
      --rejection-count 12 \\
      --promotion-count 3 \\
      --campaign-label oracle-pricing

  # Validate an existing manifest:
  python3 tools/mining-manifest.py validate <path>

  # Build manifest from a dict (Python API):
  from importlib.util import spec_from_file_location, module_from_spec
  spec = spec_from_file_location('mining_manifest', 'tools/mining-manifest.py')
  m = module_from_spec(spec); spec.loader.exec_module(m)
  payload = m.build_manifest({...})
  m.validate_manifest(payload)
  m.write_manifest(payload, Path('out.json'))

Stdlib-only. The default ``write`` command is offline-safe — it never
contacts a network, never invokes an LLM provider, and only writes JSON.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

PROVIDER_VALUES = {"kimi", "minimax", "both"}

REQUIRED_FIELDS = (
    "source_packet",
    "provider",
    "prompt_hash",
    "context_size",
    "candidate_count",
    "rejection_count",
    "promotion_count",
    "workspace",
    "campaign_date",
    "campaign_label",
    "tool_version",
    "generated_at_utc",
)

# Schema version — bump when a field is renamed or removed. Adding new
# optional fields does not require a bump.
SCHEMA_VERSION = "1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(ValueError):
    """Manifest-shape failure. Raised on validation."""


def _utc_now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


def compute_prompt_hash(text: str) -> str:
    """Deterministic SHA-256 of the prompt text.

    Important: collision resistance depends on the caller passing the
    EXACT prompt that was dispatched. Same prompt -> same hash by design
    (this is the dedup key). Different prompts that happen to produce
    the same candidate list will NOT collide because hashing is over
    the prompt text, not the candidate output. Minimax attack #2
    (collision between unrelated runs) is mitigated by:
      - hashing the FULL prompt (no truncation),
      - using SHA-256 (collision-resistant for any practical input set),
      - pinning the hash to the dispatched prompt at write time. Two
        manifests with the same prompt_hash are intentionally a dedup
        signal, not a collision: the operator should investigate why
        the same prompt was dispatched twice.
    """
    if not isinstance(text, str):
        raise TypeError("prompt text must be str, not bytes — utf-8 encode at the call site")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def estimate_context_size(text: str) -> int:
    """Heuristic token count: ``ceil(len(text) / 4)``.

    Real tokenization depends on the provider tokenizer (Kimi vs Minimax
    differ). For audit-trail purposes a stable upper-bound estimate is
    sufficient. Operator can pass an exact figure via ``--context-size``.
    """
    if not text:
        return 0
    return (len(text) + 3) // 4


def build_manifest(fields: dict) -> dict:
    """Assemble a manifest dict from operator-supplied fields.

    Auto-fills:
      - ``tool_version`` (SCHEMA_VERSION),
      - ``generated_at_utc`` if missing.
    """
    out = dict(fields)
    out.setdefault("tool_version", SCHEMA_VERSION)
    out.setdefault("generated_at_utc", _utc_now_iso())
    return out


def validate_manifest(payload: dict) -> None:
    """Raise ``ManifestError`` on shape failure; return None on success."""
    if not isinstance(payload, dict):
        raise ManifestError("manifest must be a JSON object")
    missing = [k for k in REQUIRED_FIELDS if k not in payload]
    if missing:
        raise ManifestError(f"missing required fields: {missing}")
    if payload["provider"] not in PROVIDER_VALUES:
        raise ManifestError(
            f"provider must be one of {sorted(PROVIDER_VALUES)}, "
            f"got {payload['provider']!r}"
        )
    h = payload["prompt_hash"]
    if not isinstance(h, str) or not _SHA256_RE.match(h):
        raise ManifestError(
            "prompt_hash must be a 64-char lowercase hex SHA-256 string"
        )
    cs = payload["context_size"]
    if not isinstance(cs, int) or cs <= 0:
        raise ManifestError("context_size must be a positive integer")
    cand = payload["candidate_count"]
    rej = payload["rejection_count"]
    prom = payload["promotion_count"]
    for label, val in (("candidate_count", cand), ("rejection_count", rej),
                       ("promotion_count", prom)):
        if not isinstance(val, int) or val < 0:
            raise ManifestError(f"{label} must be a non-negative integer")
    if cand < rej + prom:
        raise ManifestError(
            f"candidate_count ({cand}) < rejection_count + promotion_count "
            f"({rej + prom}); tally is inconsistent"
        )
    sc = payload.get("sampled_coverage")
    if sc is not None:
        if not isinstance(sc, dict) or {"shown", "total"} - set(sc.keys()):
            raise ManifestError(
                "sampled_coverage must have shown:int + total:int"
            )
        if not isinstance(sc["shown"], int) or not isinstance(sc["total"], int):
            raise ManifestError("sampled_coverage.shown / .total must be int")
        if sc["shown"] < 0 or sc["total"] < 0:
            raise ManifestError("sampled_coverage values must be non-negative")
        if sc["shown"] > sc["total"]:
            raise ManifestError(
                f"sampled_coverage.shown ({sc['shown']}) > total ({sc['total']})"
            )
    cd = payload["campaign_date"]
    if not isinstance(cd, str) or not re.match(r"^\d{4}-\d{2}-\d{2}$", cd):
        raise ManifestError("campaign_date must be YYYY-MM-DD")
    if payload.get("tool_version") != SCHEMA_VERSION:
        raise ManifestError(
            f"tool_version must be {SCHEMA_VERSION!r}; got "
            f"{payload.get('tool_version')!r}"
        )


def write_manifest(payload: dict, out_path: Path) -> None:
    """Write payload to disk, creating parents. Validates before writing."""
    validate_manifest(payload)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


# ---- CLI ------------------------------------------------------------------


def _cmd_write(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).expanduser()
    if not workspace.exists() and not args.allow_missing_workspace:
        print(
            f"[mining-manifest] workspace {workspace} does not exist; "
            f"use --allow-missing-workspace if this is a dry-run.",
            file=sys.stderr,
        )
        return 2
    # Resolve prompt content + hash.
    prompt_text: str = ""
    if args.prompt_file:
        prompt_text = Path(args.prompt_file).expanduser().read_text(
            errors="replace"
        )
    elif args.prompt_inline:
        prompt_text = args.prompt_inline
    if args.prompt_hash:
        prompt_hash = args.prompt_hash
    else:
        if not prompt_text:
            print(
                "[mining-manifest] need --prompt-file or --prompt-inline "
                "or --prompt-hash to fix the prompt_hash",
                file=sys.stderr,
            )
            return 2
        prompt_hash = compute_prompt_hash(prompt_text)
    context_size = (
        args.context_size if args.context_size > 0
        else estimate_context_size(prompt_text)
    )
    sampled_coverage = None
    if args.sampled_shown >= 0 and args.sampled_total > 0:
        sampled_coverage = {
            "shown": args.sampled_shown,
            "total": args.sampled_total,
        }
    payload = build_manifest({
        "source_packet": str(Path(args.source_packet).expanduser()),
        "provider": args.provider,
        "prompt_hash": prompt_hash,
        "context_size": context_size,
        "sampled_coverage": sampled_coverage,
        "candidate_count": args.candidate_count,
        "rejection_count": args.rejection_count,
        "promotion_count": args.promotion_count,
        "workspace": args.workspace_name or workspace.name,
        "campaign_date": args.date,
        "campaign_label": args.campaign_label,
    })
    try:
        validate_manifest(payload)
    except ManifestError as e:
        print(f"[mining-manifest] validation failed: {e}", file=sys.stderr)
        return 2
    out_path: Path
    if args.out:
        out_path = Path(args.out).expanduser()
    else:
        out_path = (
            workspace / "source_mining" / args.date / "mining_manifest.json"
        )
    write_manifest(payload, out_path)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[mining-manifest] wrote {out_path}")
        print(
            f"  provider={payload['provider']} "
            f"candidates={payload['candidate_count']} "
            f"rejected={payload['rejection_count']} "
            f"promoted={payload['promotion_count']} "
            f"prompt_hash={payload['prompt_hash'][:12]}…"
        )
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser()
    if not path.exists():
        print(f"[mining-manifest] not found: {path}", file=sys.stderr)
        return 2
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"[mining-manifest] invalid JSON: {e}", file=sys.stderr)
        return 2
    try:
        validate_manifest(payload)
    except ManifestError as e:
        print(f"[mining-manifest] FAIL {path}: {e}", file=sys.stderr)
        return 1
    print(f"[mining-manifest] PASS {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Source-mining manifest writer/validator (V5 Gap-26)."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pw = sub.add_parser("write", help="Write a new manifest.")
    pw.add_argument("--workspace", required=True,
                    help="Workspace path (e.g. ~/audits/<ws>).")
    pw.add_argument("--workspace-name", default=None,
                    help="Override workspace name (default: basename of "
                         "--workspace). Used for cross-check by "
                         "library-source-coverage.")
    pw.add_argument("--allow-missing-workspace", action="store_true",
                    help="Skip the workspace-exists check (dry-run).")
    pw.add_argument("--date", required=True,
                    help="Campaign date YYYY-MM-DD.")
    pw.add_argument("--campaign-label", required=True,
                    help="Domain label e.g. oracle-pricing.")
    pw.add_argument("--source-packet", required=True,
                    help="Path or stable identifier of the truth packet.")
    pw.add_argument("--provider", required=True,
                    choices=sorted(PROVIDER_VALUES))
    grp = pw.add_mutually_exclusive_group()
    grp.add_argument("--prompt-file", default=None,
                     help="Path to prompt file; SHA-256 will be computed.")
    grp.add_argument("--prompt-inline", default=None,
                     help="Inline prompt text.")
    pw.add_argument("--prompt-hash", default=None,
                    help="Override hash (use only when reproducing an "
                         "existing manifest).")
    pw.add_argument("--context-size", type=int, default=0,
                    help="Token count override; default: heuristic from "
                         "len(text) // 4.")
    pw.add_argument("--sampled-shown", type=int, default=-1)
    pw.add_argument("--sampled-total", type=int, default=-1)
    pw.add_argument("--candidate-count", type=int, required=True)
    pw.add_argument("--rejection-count", type=int, required=True)
    pw.add_argument("--promotion-count", type=int, required=True)
    pw.add_argument("--out", default=None,
                    help="Override output path. Default: "
                         "<workspace>/source_mining/<date>/mining_manifest.json")
    pw.add_argument("--json", action="store_true",
                    help="Echo the written manifest to stdout.")
    pw.set_defaults(func=_cmd_write)

    pv = sub.add_parser("validate", help="Validate an existing manifest.")
    pv.add_argument("path")
    pv.set_defaults(func=_cmd_validate)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
