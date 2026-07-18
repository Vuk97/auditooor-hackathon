// fixture: negative — proposal_expiration_reversed_operator (CLEAN)
// Fix: correct direction — now >= expiry means the proposal has expired.
module governance::proposal {
    public fun is_proposal_expired(expiry: u64, now: u64): bool {
        // Fix: expired when current time is at or past the expiry
        now >= expiry
    }
}
