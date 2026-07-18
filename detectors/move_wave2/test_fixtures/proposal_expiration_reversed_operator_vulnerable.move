// fixture: positive — proposal_expiration_reversed_operator (VULNERABLE)
// Bug: reversed comparison — expiry >= now means "not yet expired" when
// it should mean "is expired".
module governance::proposal {
    public fun is_proposal_expired(expiry: u64, now: u64): bool {
        // Bug: should be now >= expiry (expired when current time passes expiry)
        // This flags active proposals as expired and vice versa
        expiry >= now
    }
}
