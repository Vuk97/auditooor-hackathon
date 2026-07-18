// Reference shape: op-reth crates/payload/src/builder.rs#L339.
// Default (state-clear ENABLED) matches post-Spurious-Dragon spec.

#![allow(dead_code, unused_variables)]

pub struct State<DB> { _db: core::marker::PhantomData<DB> }
pub struct StateBuilder<DB> { _db: core::marker::PhantomData<DB> }

impl<DB> State<DB> {
    pub fn builder() -> StateBuilder<DB> {
        StateBuilder { _db: core::marker::PhantomData }
    }
}

impl<DB> StateBuilder<DB> {
    pub fn with_database(self, _db: DB) -> Self { self }
    pub fn with_bundle_update(self) -> Self { self }
    pub fn build(self) -> State<DB> { State { _db: core::marker::PhantomData } }
}

pub struct TrieDb;
pub struct Executor<DB> { _state: State<DB> }

pub fn build_executor(db: TrieDb) -> Executor<TrieDb> {
    // FIX: leave state-clear enabled (default).
    let state = State::builder().with_database(db).with_bundle_update().build();
    Executor { _state: state }
}
