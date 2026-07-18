// Negative fixture 2: not a gnark file — no gnark imports.
package util

// ToNAF converts a non-negative integer to its non-adjacent form.
// This is a plain Go utility function, not a gnark circuit.
func ToNAF(n int64) []int8 {
	var result []int8
	for n > 0 {
		if n%2 != 0 {
			r := int8(2 - (n % 4))
			result = append(result, r)
			n -= int64(r)
		} else {
			result = append(result, 0)
		}
		n /= 2
	}
	return result
}
