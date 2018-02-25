package set3

import (
	"cryptopals/set1"
	"log"
)

func getCTRCipherTexts(plainTexts [][]byte, key []byte, nonce []byte) [][]byte {
	var cipherTexts [][]byte

	for _, plainText := range plainTexts {
		cipherText, err := encryptAesCTRMode(plainText, key, nonce)
		if err != nil {
			log.Println("Failed to encrypt in CTR mode", err)
		}

		cipherTexts = append(cipherTexts, cipherText)
	}

	return cipherTexts
}

/**
 * Drags the crib on every position available and at the end scores the
 * plaintexts received and returns the one with the best score.
 */
func cribDrag(crib []byte, cipherText []byte) ([]byte, float32, int) {
	cribLength := len(crib)
	cipherTextLength := len(cipherText)

	var bestScore float32
	var bestPlainText []byte
	var position int

	bestScore = 0.00

	for i := 0; i < cipherTextLength-cribLength; i++ {
		plainText := set1.FixedXOR(cipherText[i:i+cribLength], crib)
		score := set1.ScoreText(plainText, nil)

		if score > bestScore && alphabetRatio(plainText) > 0 {
			bestScore = score
			bestPlainText = plainText
			position = i
		}
	}

	return bestPlainText, bestScore, position
}

/**
 * Counts how many alphabet characters are in text. If the number of
 * other characters is greater, returns a negative value.
 */
func alphabetRatio(plainText []byte) int {
	alphaCount := 0

	for _, l := range plainText {
		if (l >= 65 && l <= 90) || (l >= 97 && l <= 122) {
			alphaCount++
		}
	}

	othersCount := len(plainText) - alphaCount

	return alphaCount - othersCount
}
