package set4

import (
	"bytes"
	"cryptopals/utils"
	"testing"
)

func TestMD4(t *testing.T) {
	testArray := map[int][]byte{
		0: []byte(""),
		1: []byte("a"),
		2: []byte("abc"),
		3: []byte("message digest"),
		4: []byte("abcdefghijklmnopqrstuvwxyz"),
		5: []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
		6: []byte("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
	}

	resultArray := []string{
		"31d6cfe0d16ae931b73c59d7e0c089c0",
		"bde52cb31de33e46245e05fbdbd6fb24",
		"a448017aaf21d8525fc10ae87aa6729d",
		"d9130a8164549fe818874806e1c7014b",
		"d79e1c308aa5bbcdeea8ed63df412da9",
		"043f8582f241db351ce627e153e7f0e4",
		"e33b4ddc9c38f2199c3e7b164fcc0536",
	}

	for i, testMessage := range testArray {
		expected := resultArray[i]
		md4 := NewMD4()
		actual := md4.HexDigest(testMessage)
		if expected != actual {
			t.Error("Failed to compute MD4 for", string(testMessage), "expected", expected, "got", actual)
		}
	}
}

func TestBreakMD4SecretPrefixMAC(t *testing.T) {
	secret, err := utils.GenerateRandomBytes(16)
	if err != nil {
		t.Error("Failed to generate secret key")
	}

	message := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")

	hash := MD4SecretPrefixMAC(secret, message)

	extension := []byte(";admin=true")

	craftedInput, craftedHash := createMD4SecretPrefixMACCraftedInput(hash, message, extension, len(secret))

	if !bytes.Equal(craftedHash, MD4SecretPrefixMAC(secret, craftedInput)) {
		t.Error("Failed to create crafted MD4 hash")
	}
}
