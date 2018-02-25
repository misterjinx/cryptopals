package set2

import (
	"bytes"
	"encoding/base64"
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
	expected, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkKAQ==")
	if err != nil {
		t.Fatal("Failed to base64 decode expected output")
	}

	decrypted, err := byteAtATimeECBDecryptionSimple()
	if err != nil {
		t.Error("Failed to decrypt ECB, got error:", err)
	}

	if !bytes.Contains(decrypted, expected) {
		t.Error("Failed to decrypt ECB one byte at a time simple, expected", string(expected), "got", string(decrypted))
	}
}
