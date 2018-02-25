package set2

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestByteAtATimeECBDecryptionHarder(t *testing.T) {
	expected, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkKAQ==")
	if err != nil {
		t.Fatal("Failed to base64 decode expected output")
	}

	decrypted, err := byteAtATimeECBDecryptionHarder()
	if err != nil {
		t.Error("Failed to decrypt ECB, got error:", err)
	}

	if !bytes.Contains(decrypted, expected) {
		t.Error("Failed to decrypt ECB one byte at a time harder, expected", string(expected), "got", string(decrypted))
	}
}
