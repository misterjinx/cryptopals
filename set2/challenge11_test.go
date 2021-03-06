package set2

import (
	"bytes"
	"crypto/aes"
	"cryptopals/set1"
	"cryptopals/utils"
	"testing"
)

func TestGenerateRandomAesKey(t *testing.T) {
	key, err := utils.GenerateRandomAesKey()
	if err != nil {
		t.Error("Failed to generate random AES key. Error:", err)
	}

	if len(key) != aes.BlockSize {
		t.Error("Generated random AES key has wrong lentgh. Expected key of size", aes.BlockSize, " but got", len(key))
	}
}

func TestEncryptionOracle(t *testing.T) {
	plainText := []byte("This is a sentence of a carefully chosen length.") // 48 bytes
	cipherText, err, mode := encryptionOracle(plainText)
	if err != nil {
		t.Error("Failed to do oracle encryption.", err)
	}

	usedAesEcb := set1.DetectAes128EcbEncryption(cipherText)
	if usedAesEcb && mode != "ecb" {
		t.Error("Failed to detect oracle encryption used mode")
	}
}

func TestAes128EcbEncrypt(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")       // 16 bytes
	plainText := []byte("testTESTtestTEST") // 16 bytes

	cipherText, err := aes128ecbEncrypt(plainText, key)
	if err != nil {
		t.Error("Failed to encrypt AES ECB mode, got error:", err)
	}

	result, _ := set1.Aes128ecbDecrypt(cipherText, key)

	if !bytes.Equal(result, plainText) {
		t.Error("Failed to test AES ECB encrypt and decrypt")
	}
}
