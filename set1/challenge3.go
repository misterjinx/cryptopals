package set1

import (
	"bytes"
	"cryptopals/utils"
)

func singleXOR(input []byte, c byte) []byte {
	xored := make([]byte, len(input))

	for i := range input {
		xored[i] = input[i] ^ c
	}

	return xored
}

// simple scoring formula by adding up the frequency of each character
func ScoreText(text []byte, freqsTable map[string]float32) float32 {
	var score float32

	if len(text) == 0 {
		return 0
	}

	if freqsTable == nil {
		freqsTable = utils.Freqs
	}

	for _, c := range bytes.ToLower(text) {
		cs := string(c)
		if _, ok := freqsTable[cs]; ok {
			score += freqsTable[cs]
		}
	}

	return score
}

func DecryptSingleByteXOR(input []byte, freqsTable map[string]float32) ([]byte, byte, float32) {
	var bestScore float32
	var bestOutput []byte
	var key byte

	bestScore = 0.00

	for c := 0; c <= 255; c++ { // ascii values
		xored := singleXOR(input, byte(c))
		score := ScoreText(xored, freqsTable)

		if score > bestScore {
			bestScore = score
			bestOutput = xored
			key = byte(c)
		}
	}

	return bestOutput, key, bestScore
}
