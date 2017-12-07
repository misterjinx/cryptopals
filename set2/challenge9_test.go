package set2

import (
	"bytes"
	"testing"
)

func TestPkcs7Padding(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	size := 20

	padding := []byte{PKCS7_PAD, PKCS7_PAD, PKCS7_PAD, PKCS7_PAD}
	expected := append(input, padding...)
	actual := pkcs7padding(input, size)

	if len(actual) != size {
		t.Error("Length after applied pkcs7 padding is wrong")
	}

	if !bytes.Equal(actual, expected) {
		t.Error("Failed to apply pkcs7 padding to input")
	}
}
