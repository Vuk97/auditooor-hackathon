// Cantina/Kona finding 3.5.18: pre-fix shape.
// kona crates/proof/executor/src/builder/core.rs#L254
// `without_state_clear()` on a post-Spurious-Dragon chain diverges from op-reth.

#![allow(dead_code, unused_variables)]

pub struct State<DB> {
    _db: core::marker::PhantomData<DB>,
}

pub struct StateBuilder<DB> {
    _db: core::marker::PhantomData<DB>,
}

impl<DB> State<DB> {
    pub fn builder() -> StateBuilder<DB> {
        StateBuilder { _db: core::marker::PhantomData }
    }
}

impl<DB> StateBuilder<DB> {
    pub fn with_database(self, _db: DB) -> Self { self }
    pub fn with_bundle_update(self) -> Self { self }
    pub fn without_state_clear(self) -> Self { self }
    pub fn build(self) -> State<DB> { State { _db: core::marker::PhantomData } }
}

pub struct TrieDb;
pub struct Executor<DB> { _state: State<DB> }

pub fn build_executor(trie_db: TrieDb) -> Executor<TrieDb> {
    // BUG (kona): post-Spurious-Dragon block executor must NOT set without_state_clear.
    let state = State::builder()
        .with_database(trie_db)
        .with_bundle_update()
        .without_state_clear()
        .build();
    Executor { _state: state }
}
