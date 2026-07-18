pub fn bad(a: i128, b: i128, c: i128) -> i128 {
    // VULN: division before multiplication
    a / b * c
}

pub fn bad2(a: u128, b: u128, c: u128) -> u128 {
    (a / b) * c
}
