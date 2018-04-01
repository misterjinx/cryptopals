package set3

/**
 * Takes an MT19937 output and transforms it back into the
 * corresponding element of the MT19937 state array.
 *
 * Useful information on this at:
 *   https://jazzy.id.au/2010/09/22/cracking_random_number_generators_part_3.html
 *   https://www.maths.tcd.ie/~fionn/misc/mt.php
 */
func untemperMT19937Number(y uint32) uint32 {
	y ^= y >> 18

	y ^= y << 15 & 0xefc60000

	for i := 0; i < 7; i++ {
		y ^= y << 7 & 0x9d2c5680
	}

	for i := 0; i < 3; i++ {
		y ^= y >> 11
	}

	return y
}

func cloneMT19937(mt *MT19937) *MT19937 {
	clone := NewMT19937(0)
	for i := 0; i < 624; i++ {
		clone.States[i] = untemperMT19937Number(mt.ExtractNumber())
	}

	return clone
}
