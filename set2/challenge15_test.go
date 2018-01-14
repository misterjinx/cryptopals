package set2

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestPkcs7Unpadding(t *testing.T) {
	blockSize := aes.BlockSize

	input1 := []byte("ICE ICE BABY\x04\x04\x04\x04")
	input1Clean := []byte("ICE ICE BABY")

	unpaddedInput1, err := pkcs7unpadding(input1, blockSize)
	if err != nil || !bytes.Equal(input1Clean, unpaddedInput1) {
		t.Error("Failed to unpad input1", input1)
	}

	input2 := []byte("ICE ICE BABY\x05\x05\x05\x05")
	unpaddedInput2, err := pkcs7unpadding(input2, blockSize)
	if unpaddedInput2 != nil {
		t.Error("Failed to unpad input2", input2)
	}

	input3 := []byte("ICE ICE BABY\x01\x02\x03\x04")
	unpaddedInput3, err := pkcs7unpadding(input3, blockSize)
	if unpaddedInput3 != nil {
		t.Error("Failed to unpad input3", input3)
	}

	input4 := []byte("ICE ICE BABYBABY\x01\x02\x04")
	unpaddedInput4, err := pkcs7unpadding(input4, blockSize)
	if err == nil || unpaddedInput4 != nil {
		t.Error("Failed to unpad input4", input4)
	}

	input5 := []byte("ICE ICE")
	input5Padded := pkcs7padding(input5, aes.BlockSize)

	unpaddedInput5, err := pkcs7unpadding(input5Padded, blockSize)
	if err != nil || !bytes.Equal(input5, unpaddedInput5) {
		t.Error("Failed to unpad input5", input5)
	}
}
