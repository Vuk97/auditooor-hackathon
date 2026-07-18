// Negative fixture 2: not a gnark file — plain Go arithmetic.
package math

func addInts(a, b int64) int64 {
	return a + b
}

func mulInts(a, b int64) int64 {
	return a * b
}
