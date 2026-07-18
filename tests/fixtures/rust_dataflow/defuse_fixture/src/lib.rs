//! Rust DefUsePath fixture: an UNGUARDED multi-hop value-moving path and a
//! GUARDED multi-hop value-moving path, in the same crate.
//!
//! Both paths are >= 2 inter-procedural hops deep from a tainted fn parameter
//! to a value-moving sink (`Bank::transfer`). The ONLY difference between them
//! is that the guarded path dominates the sink with a `require`-style check on
//! the tainted amount; the unguarded path does not.
//!
//! MUTATION CONTRACT (drives the mutation-verified test):
//!   The guarded path's slice MUST be `unguarded:false` with a populated
//!   `guard_nodes`. If the `if amount > self.cap` guard inside
//!   `guarded_route` is removed (the mutant), that slice flips to
//!   `unguarded:true` with empty `guard_nodes` - exactly the unguarded path's
//!   shape. An `assert(true)` scaffold cannot make that flip happen, so the
//!   flip is the witness that the guard analysis is real (R-C non-vacuity).

/// A minimal value-moving "bank". `transfer` is the value-moving SINK; the
/// `amount` argument is the tainted value whose def-use we slice.
pub struct Bank {
    pub balance: u64,
    pub cap: u64,
}

impl Bank {
    pub fn new(balance: u64, cap: u64) -> Self {
        Bank { balance, cap }
    }

    /// VALUE-MOVING SINK. The 2nd argument (`amount`) is the tainted value.
    pub fn transfer(&mut self, _to: u64, amount: u64) -> u64 {
        self.balance = self.balance.saturating_sub(amount);
        amount
    }
}

// ---- UNGUARDED multi-hop chain --------------------------------------------
// entry_unguarded(amount) -> unguarded_route(amt) -> pay_unguarded(bank, v)
//                                                  -> bank.transfer(_, v)
// No check dominates the sink. A correct backward slice recovers the chain
// from `entry_unguarded`'s param to `Bank::transfer` with unguarded:true.

fn pay_unguarded(bank: &mut Bank, v: u64) -> u64 {
    bank.transfer(0, v)
}

fn unguarded_route(bank: &mut Bank, amt: u64) -> u64 {
    pay_unguarded(bank, amt)
}

/// ENTRYPOINT A (unguarded). `amount` is the tainted source.
pub fn entry_unguarded(bank: &mut Bank, amount: u64) -> u64 {
    unguarded_route(bank, amount)
}

// ---- GUARDED multi-hop chain ----------------------------------------------
// entry_guarded(amount) -> guarded_route(amt) [GUARD: amt <= cap] ->
//                          pay_guarded(bank, v) -> bank.transfer(_, v)
// The guard inside guarded_route dominates the downstream sink. A correct
// slice recovers the chain with unguarded:false and a guard_node.

fn pay_guarded(bank: &mut Bank, v: u64) -> u64 {
    bank.transfer(0, v)
}

fn guarded_route(bank: &mut Bank, amt: u64) -> u64 {
    // GUARD: this comparison dominates the value-moving sink below.
    // MUTATION POINT: deleting this `if` (always paying) removes the guard
    // and flips the slice to unguarded:true.
    if amt > bank.cap {
        return 0;
    }
    pay_guarded(bank, amt)
}

/// ENTRYPOINT B (guarded). `amount` is the tainted source.
pub fn entry_guarded(bank: &mut Bank, amount: u64) -> u64 {
    guarded_route(bank, amount)
}
