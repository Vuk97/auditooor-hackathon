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
pub struct SafeProtocol;
#[contractimpl]
impl SafeProtocol {
    // OK: walks from tail to get worst ICR
    pub fn require_no_undercollat(list: List) -> bool {
        let _l = list.last();
        let _lst = list.get_last();
        let iter = Iter;
        let _ = iter.prev();
        true
    }
}
