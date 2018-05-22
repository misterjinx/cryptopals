package set4

import (
	"bytes"
	"cryptopals/utils"
	"testing"
)

func TestBreakSHA1SecretPrefixMAC(t *testing.T) {
	secret, err := utils.GenerateRandomBytes(16)
	if err != nil {
		t.Error("Failed to generate secret key")
	}

	message := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")

	hash := SHA1SecretPrefixMAC(secret, message)

	extension := []byte(";admin=true")

	craftedInput, craftedHash := createSHA1SecretPrefixMACCraftedInput(hash, message, extension, len(secret))

	if !bytes.Equal(craftedHash, SHA1SecretPrefixMAC(secret, craftedInput)) {
		t.Error("Failed to create crafted SHA1 hash")
	}
}
