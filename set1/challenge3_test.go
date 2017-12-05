package set1

import (
	"bytes"
	"testing"
)

func TestDecryptSingleByteXOR(t *testing.T) {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	expected := "Cooking MC's like a pound of bacon"

	inputDecoded := decodeHex(input)
	actual, _, _ := decryptSingleByteXOR(inputDecoded)

	if !bytes.Equal(actual, []byte(expected)) {
		t.Error("Failed to decrypt single byte XOR. Expected ", expected, " got ", string(actual))
	}
}
