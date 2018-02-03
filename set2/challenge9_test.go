package set2

import (
	"bytes"
	"testing"
)

func TestPkcs7Padding(t *testing.T) {
	input1 := []byte("YELLOW SUBMARINE")
	size1 := 20

	padding1 := []byte{0x04, 0x04, 0x04, 0x04}
	expected1 := append(input1, padding1...)
	actual1 := pkcs7padding(input1, size1)

	if len(actual1) != size1 {
		t.Error("Length after applied pkcs7 padding to input1 is wrong")
	}

	if !bytes.Equal(actual1, expected1) {
		t.Error("Failed to apply pkcs7 padding to input1")
	}

	input2 := []byte("YELLOW SUBMARINE")
	size2 := 16

	padding2 := []byte{16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16}
	expected2 := append(input2, padding2...)
	actual2 := pkcs7padding(input2, size2)

	if len(actual2) != size2*2 {
		t.Error("Length after applied pkcs7 padding to input2 is wrong")
	}

	if !bytes.Equal(actual2, expected2) {
		t.Error("Failed to apply pkcs7 padding to input2")
	}
}
