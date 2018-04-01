package set3

import (
	"bytes"
	"cryptopals/utils"
	"testing"
	"time"
)

func TestMT19937StreamCipher(t *testing.T) {
	input := utils.GenerateRandomCharacters(8)
	suffix := []byte("AAAAAAAAAAAAAA")
	input = append(input, suffix...)

	t.Log("Plaintext:", string(input))

	key := uint16(time.Now().UnixNano() / int64(time.Millisecond))

	t.Log("Key:", key)

	cipherText := encryptUsingMT19937StreamCipher(input, key)

	plainText := decryptUsingMT19937StreamCipher(cipherText, key)

	t.Log("Decrypted", string(plainText))

	if !bytes.Equal(input, plainText) {
		t.Error("Failed to decrypt using MT19937 stream cipher")
	}

	recoveredKey := recoverMT19937StreamCipherKey(cipherText, suffix)
	t.Log("Recovered key:", recoveredKey)

	if key != recoveredKey {
		t.Error("Failed to recover MT19937 stream cipher key")
	}

	resetToken := generateRandomPasswordResetTokenUsingMT19937(16)

	t.Log("Reset token:", resetToken)

	if !isResetTokenGeneratedUsingMT19937(resetToken) {
		t.Error("Failed to detect the reset token was generated using MT19937")
	}

	randomToken := utils.GenerateRandomCharacters(16)
	if isResetTokenGeneratedUsingMT19937(randomToken) {
		t.Error("Detected random token was generated using MT19937")
	}
}
