package set3

import (
	"cryptopals/set1"
	"cryptopals/utils"
)

func truncateCipherTextsToCommonLength(cipherTexts [][]byte, length int) [][]byte {
	var truncated [][]byte

	for _, cipherText := range cipherTexts {
		truncated = append(truncated, cipherText[:length])
	}

	return truncated
}

func breakFixedNonceCTRStatistically(cipherTexts [][]byte, keysize int) [][]byte {
	// slightly modified version of the algorithm to break Vigenere
	var transpose [][]byte

	for i := 0; i < keysize; i++ {
		var block []byte
		for j := 0; j < len(cipherTexts); j++ {
			block = append(block, cipherTexts[j][i])
		}

		transpose = append(transpose, block)
	}

	var finalKey []byte

	for i, block := range transpose {
		var freqsTable map[string]float32

		// looking at the first results from trying to decrypt the message,
		// it appears that on the first block there are only capital letters;
		// using the general frequencies table for this doesn't detect the plain
		// text correctly, so for this block only I'm using a different
		// frequencies list
		if i == 0 {
			freqsTable = utils.FreqsFirst
		}

		_, blockKey, _ := set1.DecryptSingleByteXOR(block, freqsTable)
		finalKey = append(finalKey, blockKey)
	}

	var result [][]byte

	for _, cipherText := range cipherTexts {
		result = append(result, set1.RepeatingKeyXOR(cipherText, finalKey))
	}

	return result
}
