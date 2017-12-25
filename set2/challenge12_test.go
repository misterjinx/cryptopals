package set2

import (
	"bytes"
	"crypto/aes"
	"testing"
)

/**
 * Based on the algorithm described at http://cryptopals.com/sets/2/challenges/12
 * Some more info on this also here https://crypto.stackexchange.com/q/42891
 *
 * Also the illustration here help a lot to better understand the algorithm:
 * https://c0nradsc0rner.wordpress.com/2016/07/03/ecb-byte-at-a-time/
 */
func TestByteAtATimeECBDecryptionSimple(t *testing.T) {
	var decrypted []byte

	size := aes.BlockSize * 9 // assuming the size of the text

	for i := size - 1; i > 0; i-- {
		input := bytes.Repeat([]byte("A"), i)

		output, err := encryptionECB(input)
		if err != nil {
			t.Error("Failed to encrypt ECB, got error:", err)
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
				t.Error("Failed to encrypt ECB, got error:", err)
			}

			if bytes.Equal(encrypted[0:size], output[0:size]) {
				decrypted = append(decrypted, char)
				break
			}
		}
	}

	expected := []byte("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n")

	if !bytes.Contains(decrypted, expected) {
		t.Error("Failed to decrypt ECB one byte at a time simple, expected", string(expected), "got", string(decrypted))
	}
}
