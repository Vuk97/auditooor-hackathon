// move_fail_single_signer/SingleSigner.move
// Severity: High
// ANTI-PATTERN: single signer controls both attacker and victim roles in Move.
// Rule 44 fails with fail-no-role-separation (single signer for both roles).
// This is an opposed-trace harness (sender withholds co-sign).

module audit::single_signer_test {
    use std::signer;

    // Only one signer resource - controls both attacker and victim.
    // No separate signer for victim side.
    public fun test_opposed_trace_single_signer(admin: &signer) {
        // admin acts as both attacker and "victim" - no role separation.
        let _attacker_addr = signer::address_of(admin);
        let _victim_addr   = signer::address_of(admin); // same signer!

        // No per-role distinct signers.
        // No withheld-artifact assertion.
        // No attack-causality assertion.
    }
}
