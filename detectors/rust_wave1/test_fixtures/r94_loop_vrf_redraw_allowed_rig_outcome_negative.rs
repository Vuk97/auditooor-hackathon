use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeDraw;
#[contractimpl]
impl SafeDraw {
    // OK: rejects redraw once outcome_committed
    pub fn redraw(draw_id: u64, draw: DrawState) {
        if draw.outcome_committed { panic!("already committed"); }
        coordinator.request_random_words(draw_id);
    }
}
pub struct DrawState { pub outcome_committed: bool }
struct Coord;
impl Coord { fn request_random_words(&self, _d: u64) {} }
#[allow(non_upper_case_globals)]
static coordinator: Coord = Coord;
