package set3

import (
	"bytes"
	"math"
)

func encryptUsingMT19937StreamCipher(inputText []byte, key uint16) []byte {
	return MT19937StreamCipher(inputText, key)
}

func decryptUsingMT19937StreamCipher(cipherText []byte, key uint16) []byte {
	return MT19937StreamCipher(cipherText, key)
}

func MT19937StreamCipher(input []byte, key uint16) []byte {
	var output []byte

	prng := NewMT19937(uint32(key)) // the seed is 32bit

	for _, b := range input {
		n := prng.ExtractNumber()
		n8 := uint8(n)

		xored := b ^ n8
		output = append(output, xored)
	}

	return output
}

func recoverMT19937StreamCipherKey(cipherText []byte, plainTextKnownSuffix []byte) uint16 {
	var key uint16
	var i float64

	for i = 0; i < math.Pow(2, 16); i++ {
		curKey := uint16(i)

		dec := decryptUsingMT19937StreamCipher(cipherText, curKey)
		if bytes.HasSuffix(dec, plainTextKnownSuffix) {
			key = curKey
			break
		}
	}

	return key
}

func generateRandomPasswordResetTokenUsingMT19937(size int) []byte {
	seed := getMT19937Seed()

	token := make([]byte, size)

	prng := NewMT19937(seed)
	for i := range token {
		token[i] = uint8(prng.ExtractNumber())
	}

	return token
}

// only checks if the token could've been generated in the last day
func isResetTokenGeneratedUsingMT19937(resetToken []byte) bool {
	interval := 3600 * 24
	tokenLength := len(resetToken)
	seed := getMT19937Seed()

	var i uint32
	for i = 0; i < uint32(interval); i++ {
		prng := NewMT19937(seed - i)

		curToken := make([]byte, tokenLength)
		for j := range curToken {
			curToken[j] = uint8(prng.ExtractNumber())
		}

		if bytes.Equal(curToken, resetToken) {
			return true
		}
	}

	return false
}
