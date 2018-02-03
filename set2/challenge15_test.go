package set2

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestPkcs7unpadding(t *testing.T) {
	blockSize := aes.BlockSize

	input1 := []byte("ICE ICE BABY\x04\x04\x04\x04")
	input1Clean := []byte("ICE ICE BABY")

	unpaddedInput1, err := Pkcs7unpadding(input1, blockSize)
	if err != nil || !bytes.Equal(input1Clean, unpaddedInput1) {
		t.Error("Failed to unpad input1", input1)
	}

	input2 := []byte("ICE ICE BABY\x05\x05\x05\x05")
	unpaddedInput2, err := Pkcs7unpadding(input2, blockSize)
	if unpaddedInput2 != nil {
		t.Error("Failed to unpad input2", input2)
	}

	input3 := []byte("ICE ICE BABY\x01\x02\x03\x04")
	unpaddedInput3, err := Pkcs7unpadding(input3, blockSize)
	if unpaddedInput3 != nil {
		t.Error("Failed to unpad input3", input3)
	}

	input4 := []byte("ICE ICE BABYBABY\x01\x02\x04")
	unpaddedInput4, err := Pkcs7unpadding(input4, blockSize)
	if err == nil || unpaddedInput4 != nil {
		t.Error("Failed to unpad input4", input4)
	}

	input5 := []byte("ICE ICE")
	input5Padded := pkcs7padding(input5, aes.BlockSize)

	unpaddedInput5, err := Pkcs7unpadding(input5Padded, blockSize)
	if err != nil || !bytes.Equal(input5, unpaddedInput5) {
		t.Error("Failed to unpad input5", input5)
	}

	input6 := []byte("YELLOW SUBMARINE")
	input6Padded := pkcs7padding(input6, aes.BlockSize)

	unpaddedInput6, err := Pkcs7unpadding(input6Padded, blockSize)
	if err != nil || !bytes.Equal(input6, unpaddedInput6) {
		t.Error("Failed to unpad input6", input6)
	}

	input7 := []byte("YELLOW SUBMARINE")
	unpaddedInput7, err := Pkcs7unpadding(input7, blockSize)
	if unpaddedInput7 != nil || err == nil {
		t.Error("Failed to unpad input7", input7)
	}
}
