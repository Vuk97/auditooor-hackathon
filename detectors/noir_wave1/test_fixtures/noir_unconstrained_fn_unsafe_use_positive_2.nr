// Positive fixture: get_witness_bits is unconstrained; `bits` returned
// are used in a loop to reconstruct a value WITHOUT asserting the bits
// are a valid decomposition.
use dep::std;

unconstrained fn get_witness_bits(x: Field) -> [u1; 254] {
    x.to_le_bits(254)
}

fn use_bits_unchecked(x: Field) -> Field {
    // BUG: unconstrained bit decomposition used without constraint check
    let bits = get_witness_bits(x);
    // Missing: assert that bits correctly reconstruct x
    // i.e. sum(bits[i] * 2^i) == x must be asserted as a constraint
    let mut reconstructed: Field = 0;
    for i in 0..254 {
        reconstructed += (bits[i] as Field) * (2 as Field).pow_32(i as Field);
    }
    // returns result without constraining bits to be a valid decomposition of x
    reconstructed
}
