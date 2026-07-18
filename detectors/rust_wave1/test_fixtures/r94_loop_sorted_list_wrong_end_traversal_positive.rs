use soroban_sdk::{contract, contractimpl};
pub struct List;
impl List {
    pub fn first(&self) -> Option<u64> { None }
    pub fn last(&self) -> Option<u64> { None }
    pub fn get_first(&self) -> u64 { 0 }
    pub fn get_last(&self) -> u64 { 0 }
}
pub struct Iter;
impl Iter { pub fn next(&self) -> u64 { 0 } pub fn prev(&self) -> u64 { 0 } }
#[contract]
pub struct Protocol;
#[contractimpl]
impl Protocol {
    // BUG: requires_no_undercollat walks from head/first; worst ICR is at tail
    pub fn require_no_undercollat(list: List) -> bool {
        let _f = list.first();
        let _fst = list.get_first();
        let iter = Iter;
        let _ = iter.next();
        true
    }
}
