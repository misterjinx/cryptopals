package set1

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestDetectSingleCharXOR(t *testing.T) {
	expected, err := base64.StdEncoding.DecodeString("Tm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=")
	if err != nil {
		t.Fatal("Failed to bas64 decode expected string")
	}

	actual, _, _ := detectSingleCharXOR()

	if bytes.Equal(actual, expected) {
		t.Error("Failed to detect single char XOR. Expected", expected, "got", string(actual))
	}
}
