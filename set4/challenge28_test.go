package set4

import (
	"bytes"
	"cryptopals/utils"
	"testing"
)

func TestSHA1(t *testing.T) {
	testArray := map[int][]byte{
		0: []byte("abc"),
		1: []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
		2: []byte("a"),
		3: []byte("0123456701234567012345670123456701234567012345670123456701234567"),
	}

	resultArray := []string{
		"a9993e364706816aba3e25717850c26c9cd0d89d",
		"84983e441c3bd26ebaae4aa1f95129e5e54670f1",
		"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
		"e0c094e867ef46c350ef54a7f59dd60bed92ae83",
	}

	for i, testMessage := range testArray {
		expected := resultArray[i]
		sha1 := NewSHA1()
		actual := sha1.HexDigest(testMessage)
		if expected != actual {
			t.Error("Failed to compute SHA1 for", string(testMessage), "expected", expected, "got", actual)
		}
	}
}

func TestSHA1SecretPrefixMAC(t *testing.T) {
	key, err := utils.GenerateRandomBytes(16)
	if err != nil {
		t.Error("Failed to generate random key")
	}

	message, err := utils.GenerateRandomBytes(112)
	if err != nil {
		t.Error("Failed to generate random message")
	}

	auth := SHA1SecretPrefixMAC(key, message)

	temp, err := utils.GenerateRandomBytes(16)
	if err != nil {
		t.Error("Failed to generate random bytes to modify original message")
	}

	copy(message[15:31], temp)

	authModified := SHA1SecretPrefixMAC(key, message)

	if bytes.Equal(auth, authModified) {
		t.Error("MAC wasn't modified when message changed")
	}

	authUnknownKey := SHA1SecretPrefixMAC(nil, message)
	if bytes.Equal(authModified, authUnknownKey) {
		t.Error("MAC with unknown key equals initial MAC")
	}
}
