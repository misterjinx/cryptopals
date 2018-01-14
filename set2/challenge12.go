package set2

import (
	"bytes"
	"encoding/base64"
)

const UNKNOWN_KEY = "QeGK6ThvFTuFa27R"

func encryptionECB(plainText []byte) ([]byte, error) {
	key := []byte(UNKNOWN_KEY)

	var finalPlainText []byte

	finalPlainText = append(finalPlainText, plainText...)

	unknownText, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	if err != nil {
		return nil, err
	}

	finalPlainText = append(finalPlainText, unknownText...)

	cipherText := make([]byte, len(finalPlainText))

	cipherText, err = aes128ecbEncrypt(finalPlainText, key)
	if err != nil {
		return nil, err
	}

	return cipherText, nil
}

/**
 * Based on the algorithm described at http://cryptopals.com/sets/2/challenges/12
 * Some more info on this also here https://crypto.stackexchange.com/q/42891
 *
 * Also the illustrations here help a lot to better understand the algorithm:
 * https://c0nradsc0rner.wordpress.com/2016/07/03/ecb-byte-at-a-time/
 */
func byteAtATimeECBDecryptionSimple() ([]byte, error) {
	// determine the size of the ciphertext
	a, _ := encryptionECB([]byte("A"))
	size := len(a)

	var decrypted []byte

	for i := size - 1; i > 0; i-- {
		input := bytes.Repeat([]byte("A"), i)

		output, err := encryptionECB(input)
		if err != nil {
			return nil, err
		}

		craftedInput := make([]byte, size)
		copy(craftedInput, input)
		decryptedLength := len(decrypted)
		if decryptedLength > 0 {
			copy(craftedInput[i:i+decryptedLength], decrypted)
		}

		for c := 0; c <= 255; c++ { // ascii characters
			char := byte(c)
			craftedInput[size-1] = char

			encrypted, err := encryptionECB(craftedInput)
			if err != nil {
				return nil, err
			}

			if bytes.Equal(encrypted[0:size], output[0:size]) {
				decrypted = append(decrypted, char)
				break
			}
		}
	}

	return decrypted, nil
}
