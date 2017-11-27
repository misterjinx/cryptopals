package set1

import (
	"strings"
)

// source: http://www.data-compression.com/english.html
// chose this frequencies list because it contains
// the space character also
var freqs = map[string]float32{
	"a": 0.0651738,
	"b": 0.0124248,
	"c": 0.0217339,
	"d": 0.0349835,
	"e": 0.1041442,
	"f": 0.0197881,
	"g": 0.0158610,
	"h": 0.0492888,
	"i": 0.0558094,
	"j": 0.0009033,
	"k": 0.0050529,
	"l": 0.0331490,
	"m": 0.0202124,
	"n": 0.0564513,
	"o": 0.0596302,
	"p": 0.0137645,
	"q": 0.0008606,
	"r": 0.0497563,
	"s": 0.0515760,
	"t": 0.0729357,
	"u": 0.0225134,
	"v": 0.0082903,
	"w": 0.0171272,
	"x": 0.0013692,
	"y": 0.0145984,
	"z": 0.0007836,
	" ": 0.1918182,
}

func singleXOR(hexString string, c byte) []byte {
	decodedString := decodeHex(hexString)
	xored := make([]byte, len(decodedString))

	for i := range decodedString {
		xored[i] = decodedString[i] ^ c
	}

	return xored
}

// simple scoring formula by adding up the frequency of each character
func scoreText(text string) float32 {
	var score float32

	if len(text) == 0 {
		return 0
	}

	for _, c := range strings.ToLower(text) {
		cs := string(c)
		if _, ok := freqs[cs]; ok {
			score += freqs[cs]
		}
	}

	return score
}

func decryptSingleByteXOR(hexString string) ([]byte, byte, float32) {
	var bestScore float32
	var bestOutput []byte
	var key byte

	bestScore = 0.00

	for c := 0; c <= 255; c++ { // ascii values
		xored := singleXOR(hexString, byte(c))
		score := scoreText(string(xored))

		if score > bestScore {
			bestScore = score
			bestOutput = xored
			key = byte(c)
		}
	}

	return bestOutput, key, bestScore
}