package set3

/**
 * https://en.wikipedia.org/wiki/Mersenne_Twister
 */

// w = 32 (word size, number of bits)
const n = 624        // degree of recurrence
const m = 397        // middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
const r = 31         // separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
const a = 0x9908b0df // coefficients of the rational normal form twist matrix

// b, c: TGFSR(R) tempering bitmasks
// s, t: TGFSR(R) tempering bit shifts
// u, d, l: additional Mersenne Twister tempering bit shifts/masks
const u = 11
const d = 0x7fffffff
const s = 7
const b = 0x9d2c5680
const t = 15
const c = 0xefc60000
const l = 18

const f = 1812433253 // constant for the generator

type MT19937 struct {
	Seed   uint32
	Index  uint32
	States [n]uint32
}

func (mt *MT19937) Init() {
	mt.Index = n

	mt.States[0] = mt.Seed

	var i uint32
	for i = 1; i < n; i++ {
		mt.States[i] = f*(mt.States[i-1]^mt.States[i-1]>>30) + i
	}
}

func (mt *MT19937) ExtractNumber() uint32 {
	if mt.Index >= n {
		mt.Twist()
	}

	y := mt.States[mt.Index]

	// Right shift by u = 11 bits
	y = y ^ (y >> u)
	// Shift y left by s = 7 and take the bitwise and of b
	y = y ^ ((y << s) & b)
	// Shift y left by t = 15 and take the bitwise and of y and c
	y = y ^ ((y << t) & c)
	// Right shift by l = 18 bits
	y = y ^ (y >> l)

	mt.Index += 1

	return y
}

func (mt *MT19937) Twist() {
	for i := 0; i < n; i++ {
		y := (mt.States[i] & 0x80000000) + (mt.States[(i+1)%n] & 0x7fffffff)
		mt.States[i] = mt.States[(i+m)%n] ^ y>>1

		if y%2 != 0 {
			mt.States[i] = mt.States[i] ^ a
		}
	}

	mt.Index = 0
}

func NewMT19937(seed uint32) *MT19937 {
	twister := &MT19937{
		Seed: seed,
	}
	twister.Init()

	return twister
}
