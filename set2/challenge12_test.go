package set2

import (
	"bytes"
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
	expected := []byte("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n")
	decrypted, err := byteAtATimeECBDecryptionSimple()
	if err != nil {
		t.Error("Failed to decrypt ECB, got error:", err)
	}

	if !bytes.Contains(decrypted, expected) {
		t.Error("Failed to decrypt ECB one byte at a time simple, expected", string(expected), "got", string(decrypted))
	}
}
