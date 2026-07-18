#!/usr/bin/env python3
"""overnight-queue-builder.py — generate the JSONL task queue + per-task prompt files
for tools/overnight-llm-loop.sh.

Tasks generated (high-leverage, one-shot, idempotent):

A. CATALOG → DSL EXTRACTION (Kimi, long-context)
   For each pattern class section in reference/solodit_pattern_catalog.md:
   one prompt asking Kimi to emit a structured YAML DSL pattern definition
   matching the existing schema in reference/patterns.dsl.r94_solodit_*.

B. TIER-E DETECTOR ADVERSARIAL REVIEW (Minimax)
   For the first N Tier-E detectors in detectors/_tier_registry.yaml:
   one prompt asking Minimax to review the detector's fixture pair, return
   a structured verdict (promote / hold / demote) with rationale.

C. PASTE-READY ADVERSARIAL REVIEW (Minimax)
   For each FN2/FN3/FN6 paste-ready: ask Minimax to play hostile triager
   and surface the strongest objection that would land the report in
   "needs more info" or "OOS" buckets.

D. RUST AUDIT CORPUS PATTERN MINING (Kimi)
   Per-source: ask Kimi to enumerate published security-relevant findings
   from a named source (Code4rena Solana-X, Sherlock Substrate-Y, ...)
   into structured JSON rows.

Output:
  <work_dir>/queue.jsonl         (the queue feeding overnight-llm-loop.sh)
  <work_dir>/prompts/*.txt       (per-task prompt files)
  <work_dir>/outputs/            (where llm-dispatch results land)
"""
from __future__ import annotations

import argparse
import json
import re
import textwrap
import yaml
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CATALOG = REPO / "reference" / "solodit_pattern_catalog.md"
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:80]


def build_catalog_dsl_tasks(work_dir: Path, max_tasks: int) -> list[dict]:
    """A. catalog → DSL extraction. One task per pattern class header."""
    tasks: list[dict] = []
    text = CATALOG.read_text(encoding="utf-8").splitlines()

    # Parse all `### <Title> (<count> findings: ...)` blocks.
    blocks: list[tuple[str, list[str]]] = []
    current_title: str | None = None
    current_lines: list[str] = []
    for line in text:
        if line.startswith("### "):
            if current_title:
                blocks.append((current_title, current_lines))
            current_title = line[4:].strip()
            current_lines = [line]
        elif current_title:
            current_lines.append(line)
    if current_title:
        blocks.append((current_title, current_lines))

    for title, body in blocks[:max_tasks]:
        slug = _slug(title.split("(", 1)[0].strip())
        if not slug:
            continue
        prompt = textwrap.dedent(f"""\
            You are extracting a structured Solodit DSL pattern definition from a
            single Solodit pattern-catalog block. The block describes a real bug
            class observed across many findings on Solodit.

            === BLOCK START ===
            {chr(10).join(body[:120])}
            === BLOCK END ===

            Emit ONE YAML document matching the existing
            `reference/patterns.dsl.r94_solodit_*` schema. Required fields:

              id: <kebab-case-id-distinct-and-actionable>
              title: |
                <one-line title>
              severity: <Critical|High|Medium|Low>     # the modal severity from the block
              language: solidity                       # default solidity unless block says otherwise
              platform: ethereum                       # ethereum unless otherwise stated
              source: solodit
              source_id: "{slug}"
              firm: 'Solodit'
              quality_score: 3
              rarity_score: 2
              tags: [<3-5 short tokens>]
              bug_class: <one-of business-logic|signature-auth|access-control|rewards-accounting|oracle-cascade|arithmetic|liquidation|input-validation|reentrancy|domain-separation|other>
              indicators:
                - 'text-pattern: <indicator-1>'
                - 'text-pattern: <indicator-2>'
                - 'grep-pattern: <regex-1>'
              victim: <one-line victim characterization>
              exploit_precondition: <one-line precondition>
              real_world_example: |
                <2-line example summary>
              fix_sketch: |
                <2-line fix sketch>

            Return ONLY the YAML document (no markdown fence, no commentary).
            Indicators must be specific (function names, variable names,
            grep regexes), not generic prose.
            """).strip()

        prompt_path = work_dir / "prompts" / f"catalog_dsl_{slug}.txt"
        output_path = work_dir / "outputs" / f"catalog_dsl_{slug}.yaml"
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"catalog-dsl-{slug}",
            "provider": "kimi",
            "task_type": "source-extract",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 4000,
        })
    return tasks


def build_tier_e_review_tasks(work_dir: Path, max_tasks: int) -> list[dict]:
    """B. Tier-E detector adversarial review. One task per detector with a fixture pair."""
    tasks: list[dict] = []
    with TIER_REGISTRY.open() as f:
        registry = yaml.safe_load(f)

    e_detectors: list[tuple[str, dict]] = [
        (name, meta) for name, meta in registry.get("tiers", {}).items()
        if meta.get("tier") == "E" and meta.get("fixture_pair")
    ]

    for name, meta in e_detectors[:max_tasks]:
        slug = _slug(name)
        fixture_pair = meta.get("fixture_pair", "")
        wave = (meta.get("waves") or ["unknown"])[0]

        # Fixture pairs live primarily under detectors/test_fixtures/<id>_{clean,vulnerable}.sol.
        # The fixture_pair field in the registry is metadata; the on-disk layout is flat.
        # Try the canonical location first, then a few historical layouts.
        fixture_basename = Path(fixture_pair).name if fixture_pair else slug.replace("-", "_")
        candidate_clean_paths = [
            REPO / "detectors" / "test_fixtures" / f"{fixture_basename}_clean.sol",
            REPO / "detectors" / fixture_pair / f"{fixture_basename}_clean.sol",
            REPO / "detectors" / f"{fixture_pair}_clean.sol",
            REPO / "detectors" / fixture_pair.split("/", 1)[0] / f"{fixture_basename}_clean.sol",
        ] if fixture_pair else [
            REPO / "detectors" / "test_fixtures" / f"{slug.replace('-', '_')}_clean.sol",
        ]
        candidate_vuln_paths = [Path(str(p).replace("_clean.sol", "_vulnerable.sol")) for p in candidate_clean_paths]
        clean_path = next((p for p in candidate_clean_paths if p.exists()), None)
        vuln_path = next((p for p in candidate_vuln_paths if p.exists()), None)

        if not clean_path or not vuln_path:
            # No fixture pair on disk — skip this detector. The Minimax review for
            # a missing-fixture detector is uninformative ("demote_to_D — fixtures
            # missing"); better to skip and surface the gap as a separate task.
            continue

        clean_text = clean_path.read_text(encoding="utf-8")[:6000]
        vuln_text = vuln_path.read_text(encoding="utf-8")[:6000]

        prompt = textwrap.dedent(f"""\
            You are a hostile auditor reviewing a Tier-E (experimental, unvalidated)
            DSL detector for a Solodit-derived bug pattern. Your job: read the
            fixture pair (clean + vulnerable variants) and decide whether the
            detector should be PROMOTED to Tier B (real signal), HELD at Tier E
            (ambiguous), or DEMOTED to Tier D (no real signal).

            Detector ID: {name}
            Wave: {wave}
            Fixture pair: detectors/{fixture_pair}/

            === CLEAN VARIANT (should NOT trigger) ===
            {clean_text}

            === VULNERABLE VARIANT (should trigger) ===
            {vuln_text}

            Output ONE JSON object (no markdown fence, no commentary) with fields:
              detector_id: "{name}"
              verdict: "promote_to_B" | "hold_E" | "demote_to_D"
              precision_estimate: 0.0..1.0
              clean_variant_quality: "good" | "weak" | "broken"
              vulnerable_variant_quality: "good" | "weak" | "broken"
              fixture_discriminates_real_bug: true | false
              rationale: "<2-3 sentences>"
              recommended_fixture_additions: ["<short suggestion>", ...]

            Be strict. Many Tier-E detectors are over-fitted to a single
            finding's wording and would fire on benign code. Prefer
            demote_to_D unless the fixture clearly demonstrates a
            non-trivial discrimination.
            """).strip()

        prompt_path = work_dir / "prompts" / f"tier_e_{slug}.txt"
        output_path = work_dir / "outputs" / f"tier_e_{slug}.json"
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"tier-e-{slug}",
            "provider": "minimax",
            "task_type": "adversarial-kill",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 1500,
        })
    return tasks


def build_adversarial_review_tasks(work_dir: Path) -> list[dict]:
    """C. Hostile triager review of FN2/FN3/FN6 paste-readies."""
    tasks: list[dict] = []
    targets = [
        ("/Users/wolf/audits/base-azul/submissions/paste_ready/current/FN2_CRITICAL_FINAL_PASTE.md", "FN2"),
        ("/Users/wolf/audits/base-azul/submissions/paste_ready/current/FN3_HIGH_FINAL_PASTE.md", "FN3"),
        ("/Users/wolf/audits/base-azul/submissions/paste_ready/current/FN6_MEDIUM_FINAL_PASTE.md", "FN6"),
    ]
    for path, fid in targets:
        p = Path(path)
        if not p.exists():
            continue
        body = p.read_text(encoding="utf-8")
        truncated = body[:30000]
        prompt = textwrap.dedent(f"""\
            ROLE: Hostile Immunefi triager reviewing the submission below.
            GOAL: Surface the SINGLE strongest objection that would lead to
            OOS / needs_more_info / downgrade. Be maximally skeptical.

            === PASTE-READY START ({fid}) ===
            {truncated}
            === PASTE-READY END ===

            OUTPUT FORMAT — STRICT:
            Return ONLY a single-line minified JSON object. No markdown
            fence. No prose. No reasoning. No leading or trailing whitespace.
            Begin your response with `{{"` and end with `}}`. Do not write
            anything before or after the JSON.

            REQUIRED FIELDS (all string-typed):
              "finding_id": "{fid}"
              "strongest_objection": one-sentence
              "objection_category": "OOS" or "needs_more_info" or "downgrade" or "duplicate" or "no_objection"
              "objection_target_section": short section name
              "objection_target_line_excerpt": 5-15 word quote
              "defensibility_estimate": "high" or "medium" or "low"
              "recommended_fix": one-sentence
              "file_anyway": "yes" or "no"
            """).strip()

        prompt_path = work_dir / "prompts" / f"adversarial_{fid}.txt"
        output_path = work_dir / "outputs" / f"adversarial_{fid}.json"
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"adversarial-{fid}",
            "provider": "minimax",
            "task_type": "adversarial-kill",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 4000,
        })
    return tasks


def build_rust_corpus_seed_tasks(work_dir: Path) -> list[dict]:
    """D. Rust audit corpus pattern-mining seeds. Each task asks Kimi to
    enumerate published Rust security findings from one named source."""
    sources = [
        ("trail-of-bits-lighthouse", "Trail of Bits — Lighthouse (Eth2 client) audit reports", "rust", "ethereum"),
        ("trail-of-bits-reth", "Trail of Bits — reth audit reports", "rust", "ethereum"),
        ("trail-of-bits-near", "Trail of Bits — NEAR Protocol audit reports", "rust", "near"),
        ("kudelski-zksync", "Kudelski Security — zkSync (Era) Rust runtime audit reports", "rust", "zksync"),
        ("ottersec-solana", "OtterSec — Solana program audit reports", "rust", "solana"),
        ("ottersec-anchor", "OtterSec — Anchor framework audit reports", "rust", "solana"),
        ("hacken-substrate", "Hacken — Substrate / Polkadot pallet audits", "rust", "polkadot"),
        ("oak-security-cosmwasm", "Oak Security — CosmWasm audit reports", "rust", "cosmos"),
        ("zellic-aptos", "Zellic — Aptos / Move audits", "rust", "aptos"),
        ("zellic-sui", "Zellic — Sui / Move audits", "rust", "sui"),
        ("certora-rust", "Certora — Rust formal-verification audit reports", "rust", "multi-chain"),
        ("spearbit-cyfrin-rust", "Spearbit / Cyfrin — Rust audit reports (any chain)", "rust", "multi-chain"),
        ("oss-fuzz-rust-security", "OSS-Fuzz — Rust security-tagged crash reports", "rust", "multi-chain"),
    ]
    tasks: list[dict] = []
    for slug, desc, lang, platform in sources:
        prompt = textwrap.dedent(f"""\
            You have broad knowledge of public security audit reports. Enumerate
            up to 25 published security-relevant findings from this source:

              SOURCE: {desc}
              LANGUAGE FILTER: {lang}
              PLATFORM: {platform}

            Output ONE JSON array (no markdown fence, no commentary). Each
            element is a finding row:

              {{
                "finding_id": "<source-slug>-<short-id>",
                "title": "<full title>",
                "severity": "<Critical|High|Medium|Low|Informational>",
                "language": "{lang}",
                "platform": "{platform}",
                "firm": "<auditing firm>",
                "victim": "<protocol/project>",
                "report_url": "<URL if known, else empty>",
                "public_fix_commit": "<commit SHA or PR link if known>",
                "bug_class": "<one-of memory-safety|integer|decode-deserialization|concurrency|crypto|consensus|substrate-weight|solana-account|move-resource|other>",
                "indicators": ["<grep/text pattern>", "<grep/text pattern>"],
                "one_line_summary": "<single sentence>"
              }}

            Only include findings you have meaningful knowledge of. Empty
            fields are acceptable; fabrication is not. If you cannot
            enumerate any with confidence, return [].

            Be precise about severity (use the firm's published severity).
            Return only the JSON array, max 25 elements.
            """).strip()

        prompt_path = work_dir / "prompts" / f"rust_corpus_{slug}.txt"
        output_path = work_dir / "outputs" / f"rust_corpus_{slug}.json"
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"rust-corpus-{slug}",
            "provider": "kimi",
            "task_type": "source-extract",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 6000,
        })
    return tasks


def build_dsl_to_fixture_tasks(work_dir: Path, max_tasks: int) -> list[dict]:
    """E. For each existing DSL pattern in reference/patterns.dsl.r94_solodit_*/,
    ask Kimi to author a Solidity fixture pair (clean.sol + vulnerable.sol)
    + an executable detector spec (Slither-compatible YAML). The fixture
    pair feeds tools/detector-validator.py for tier promotion."""
    tasks: list[dict] = []
    pattern_dirs = sorted((REPO / "reference").glob("patterns.dsl.r94_solodit_*"))
    yaml_files: list[Path] = []
    for pd in pattern_dirs:
        yaml_files.extend(sorted(pd.glob("*.yaml")))
    yaml_files = yaml_files[:max_tasks]

    for yf in yaml_files:
        try:
            spec = yaml.safe_load(yf.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not spec or spec.get("language") not in ("solidity", None):
            # Phase 1 focuses on Solidity. Skip Rust/Move/etc for this batch.
            continue
        slug = _slug(spec.get("id", yf.stem))
        spec_text = yf.read_text(encoding="utf-8")
        prompt = textwrap.dedent(f"""\
            You are converting an existing structured Solodit DSL bug-pattern
            spec into a Foundry-runnable fixture pair AND a Slither-compatible
            detector specification, suitable for our automated tier-promotion
            pipeline.

            === DSL SPEC START ===
            {spec_text}
            === DSL SPEC END ===

            Your job: emit ONE JSON document (no markdown fence) with these fields:

              spec_id: "{slug}"
              fixture_pair_clean_sol: |
                <complete Solidity 0.8.x source for a CLEAN variant —
                 ~50–150 LOC contract that does NOT exhibit the bug.
                 Must compile under solc 0.8.20+ as a self-contained file.
                 Include all imports inline as bare interfaces or simple
                 stubs; do NOT use OpenZeppelin imports.>
              fixture_pair_vulnerable_sol: |
                <complete Solidity 0.8.x source for a VULNERABLE variant —
                 same shape as clean, but exhibiting the exact bug pattern.
                 Should be syntactically valid and compile.>
              fixture_discriminator_explanation: |
                <2–3 sentence explanation of WHAT changed between clean
                 and vulnerable, mapped to the bug pattern.>
              detector_spec:
                pattern_id: "<kebab-case>"
                slither_or_dsl: "slither" | "ast-grep" | "regex"
                detector_indicators:
                  - "<specific function name, AST shape, or regex>"
                  - "<another indicator>"
                expected_clean_hits: 0
                expected_vulnerable_hits_min: 1
                expected_vulnerable_hits_max: 5
                false_positive_avoidance_notes: "<short>"

            CONSTRAINTS:
            - Both .sol files must be self-contained and compile.
            - The discriminator (clean vs vulnerable) must be tightly scoped —
              the detector should fire ONLY on the bug pattern, not on
              syntactically similar but semantically different code.
            - Do NOT use external imports (OpenZeppelin, etc.). Use minimal
              inline interface stubs.
            - Output JSON only.
            """).strip()

        prompt_path = work_dir / "prompts" / f"dsl_to_fixture_{slug}.txt"
        output_path = work_dir / "outputs" / f"dsl_to_fixture_{slug}.json"
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"dsl-to-fixture-{slug}",
            "provider": "kimi",
            "task_type": "fixture-map",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 8000,
        })
    return tasks


def build_solodit_url_mining_tasks(work_dir: Path, max_tasks: int) -> list[dict]:
    """F. For each DSL pattern with a `source_url`, ask Kimi to enrich it
    using its long-context knowledge. Kimi names the public-fix commit
    URL/SHA when known, sketches the diff shape, and proposes detector
    indicators tightened to the actual fix pattern."""
    tasks: list[dict] = []
    pattern_dirs = sorted((REPO / "reference").glob("patterns.dsl.r94_solodit_*"))
    yaml_files: list[Path] = []
    for pd in pattern_dirs:
        yaml_files.extend(sorted(pd.glob("*.yaml")))

    enriched = 0
    for yf in yaml_files:
        if enriched >= max_tasks:
            break
        try:
            spec = yaml.safe_load(yf.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not spec or not spec.get("source_url"):
            continue
        slug = _slug(spec.get("id", yf.stem))
        spec_text = yf.read_text(encoding="utf-8")
        prompt = textwrap.dedent(f"""\
            You are enriching a Solodit-derived DSL bug-pattern spec with
            public-fix-commit intelligence. The pattern below has a
            `source_url` to the original Solodit issue page.

            === DSL SPEC START ===
            {spec_text}
            === DSL SPEC END ===

            Use your knowledge of public audit reports and GitHub fix
            commits. For the protocol named in this spec, identify (if you
            know it):

            - The GitHub repo of the affected protocol
            - The SPECIFIC fix commit SHA or PR number that addressed
              this finding
            - The 1–2 line shape of the diff (what was added/removed)
            - Tightened detector indicators based on the ACTUAL fix
              (not on the prose Solodit description)

            Output ONE JSON document (no markdown fence):

              spec_id: "{slug}"
              protocol_repo_url: "<github.com/X/Y or empty>"
              public_fix_commit_sha: "<SHA or empty>"
              public_fix_pr_url: "<URL or empty>"
              fix_diff_shape: "<2-line shape — added X check, removed Y assumption, etc.>"
              tightened_indicators:
                - "<specific>"
                - "<specific>"
              confidence: "high" | "medium" | "low" | "unknown"
              one_line_attack_under_audit: "<the attack the fix prevents>"

            If you do not have meaningful knowledge of the fix, set
            confidence to "unknown" and leave commit/PR fields empty.
            DO NOT FABRICATE commit SHAs or URLs. Empty is fine.
            """).strip()

        prompt_path = work_dir / "prompts" / f"solodit_url_{slug}.txt"
        output_path = work_dir / "outputs" / f"solodit_url_{slug}.json"
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"solodit-url-{slug}",
            "provider": "kimi",
            "task_type": "source-extract",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 2500,
        })
        enriched += 1
    return tasks


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--work-dir", type=Path, required=True,
                   help="Output directory for queue + prompts + outputs.")
    p.add_argument("--catalog-tasks", type=int, default=204,
                   help="Number of catalog→DSL tasks (default: all 204).")
    p.add_argument("--tier-e-tasks", type=int, default=300,
                   help="Number of Tier-E review tasks (default: 300, ~all).")
    p.add_argument("--dsl-fixture-tasks", type=int, default=200,
                   help="Number of DSL→fixture-pair tasks (Solidity only).")
    p.add_argument("--solodit-url-tasks", type=int, default=200,
                   help="Number of Solodit URL enrichment tasks.")
    args = p.parse_args()

    work_dir = args.work_dir
    work_dir.mkdir(parents=True, exist_ok=True)

    all_tasks: list[dict] = []
    all_tasks.extend(build_adversarial_review_tasks(work_dir))      # 3 minimax (cheap, fast)
    all_tasks.extend(build_rust_corpus_seed_tasks(work_dir))         # 13 kimi (long-context)
    all_tasks.extend(build_tier_e_review_tasks(work_dir, args.tier_e_tasks))   # ~300 minimax
    all_tasks.extend(build_catalog_dsl_tasks(work_dir, args.catalog_tasks))    # 204 kimi
    all_tasks.extend(build_dsl_to_fixture_tasks(work_dir, args.dsl_fixture_tasks))  # ≤200 kimi
    all_tasks.extend(build_solodit_url_mining_tasks(work_dir, args.solodit_url_tasks))  # ≤200 kimi

    queue_path = work_dir / "queue.jsonl"
    with queue_path.open("w") as f:
        for t in all_tasks:
            f.write(json.dumps(t) + "\n")

    by_provider: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for t in all_tasks:
        by_provider[t["provider"]] = by_provider.get(t["provider"], 0) + 1
        by_type[t["task_type"]] = by_type.get(t["task_type"], 0) + 1

    print(f"queue: {queue_path}")
    print(f"total tasks: {len(all_tasks)}")
    print(f"by provider: {by_provider}")
    print(f"by task_type: {by_type}")
    print(f"prompts: {work_dir / 'prompts'}")
    print(f"outputs: {work_dir / 'outputs'}")
    print(f"\nRun:\n  bash tools/overnight-llm-loop.sh {queue_path} 15")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
