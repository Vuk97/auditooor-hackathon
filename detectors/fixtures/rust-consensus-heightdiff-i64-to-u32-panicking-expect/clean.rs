// CLEAN fixture: should NOT fire.
// Same shape as the positive fixture but with a sign guard before the
// try_into() call - the function returns None when the intermediate
// value would be negative.

type Height = u32;
type HeightDiff = i64;

struct Network;

impl Network {
    fn height_for_first_halving(&self) -> Height { 1_000_000 }
    fn post_blossom_halving_interval(&self) -> HeightDiff { 1_051_200 }
    fn funding_stream_address_change_interval(&self) -> HeightDiff { 21_900 }
}

/// Safe version: returns None when height is before the first halving,
/// avoiding the panic on negative address_period.
pub fn funding_stream_address_period_safe(height: Height, network: &Network) -> Option<u32> {
    let height_after_first_halving =
        (height as i64) - (network.height_for_first_halving() as i64);

    // Guard: reject negative intermediate value before narrowing
    if height_after_first_halving < 0 {
        return None;
    }

    let address_period = (height_after_first_halving + network.post_blossom_halving_interval())
        / network.funding_stream_address_change_interval();

    address_period.try_into().ok()
}
