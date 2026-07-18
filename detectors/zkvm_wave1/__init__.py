"""zkvm_wave1 - zk-VM / bespoke-proof-system native regex detectors.

Unlike arkworks_wave1 / bellperson_wave1 (which gate on a specific ZK *framework*
import), these detectors gate on GENERIC proof-system signals (Poseidon, sponge,
challenger, transcript, sumcheck, tweakable hash, field modulus). They are built to
fire on BESPOKE proof systems (e.g. leanEthereum/leanVM) that implement their own
field / PCS / Fiat-Shamir stack and therefore match no framework-specific detector.

API: each detector exposes ``run_text(source: str, filepath: str) -> list[dict]``
returning {detector_id, line, col, severity, message, snippet}.
"""
