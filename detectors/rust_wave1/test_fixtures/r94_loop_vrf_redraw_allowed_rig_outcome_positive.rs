use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Draw;
#[contractimpl]
impl Draw {
    // BUG: redraw lets host re-request random words without outcome-committed check
    pub fn redraw(draw_id: u64) {
        coordinator.request_random_words(draw_id);
    }
}
struct Coord;
impl Coord { fn request_random_words(&self, _d: u64) {} }
#[allow(non_upper_case_globals)]
static coordinator: Coord = Coord;
