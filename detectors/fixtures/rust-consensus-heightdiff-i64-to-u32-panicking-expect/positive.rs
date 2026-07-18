// POSITIVE fixture: should fire.
// Mirrors the real Zebra funding_stream_address_period pattern:
// height subtraction -> arithmetic -> try_into().expect() with no sign guard.

type Height = u32;
type HeightDiff = i64;

struct Network;

impl Network {
    fn height_for_first_halving(&self) -> Height { 1_000_000 }
    fn post_blossom_halving_interval(&self) -> HeightDiff { 1_051_200 }
    fn funding_stream_address_change_interval(&self) -> HeightDiff { 21_900 }
}

/// Compute the address period for a funding stream at the given height.
/// On custom networks where height < height_for_first_halving, the
/// subtraction yields a negative HeightDiff and the try_into().expect()
/// will panic.
pub fn funding_stream_address_period(height: Height, network: &Network) -> u32 {
    let height_after_first_halving = (height as i64) - (network.height_for_first_halving() as i64);

    let address_period = (height_after_first_halving + network.post_blossom_halving_interval())
        / network.funding_stream_address_change_interval();

    address_period
        .try_into()
        .expect("all values are positive and smaller than the input height")
}
