package set3

import (
	"bytes"
	"crypto/aes"
	"cryptopals/set2"
	"cryptopals/utils"
	"encoding/base64"
	"testing"
)

func TestCbcOraclePadding(t *testing.T) {
	key, err := utils.GenerateRandomAesKey()
	if err != nil {
		t.Error("Failed to generate random AES key:", err)
	}

	iv, err := utils.GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		t.Error("Failed to generate random IV:", err)
	}

	randomBase64String := getRandomString()

	cipherText, err := encryptCBCString(randomBase64String, key, iv)
	if err != nil {
		t.Error("Failed to CBC encrypt random string:", err)
	}

	plainText := decryptCBCPaddingOracle(cipherText, key, iv)

	unpaddedPlainText, err := set2.Pkcs7unpadding(plainText, aes.BlockSize)
	if err != nil {
		t.Error("Failed to unpad final plain text:", err)
	}

	randomString, err := base64.StdEncoding.DecodeString(randomBase64String)
	if err != nil {
		t.Error("Failed to base64 decode random string:", err)
	}

	if !bytes.Equal(randomString, unpaddedPlainText) {
		t.Error("Failed to decrypt random string using CBC padding oracle attack")
	}
}
