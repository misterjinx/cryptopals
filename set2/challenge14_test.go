package set2

import (
	"bytes"
	"testing"
)

func TestByteAtATimeECBDecryptionHarder(t *testing.T) {
	expected := []byte("Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n")
	decrypted, err := byteAtATimeECBDecryptionHarder()
	if err != nil {
		t.Error("Failed to decrypt ECB, got error:", err)
	}

	if !bytes.Contains(decrypted, expected) {
		t.Error("Failed to decrypt ECB one byte at a time harder, expected", string(expected), "got", string(decrypted))
	}
}
