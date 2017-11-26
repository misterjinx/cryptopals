package set1

import (
	"testing"
)

func TestDecryptSingleByteXOR(t *testing.T) {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	expected := "Cooking MC's like a pound of bacon"

	actual, _, _ := decryptSingleByteXOR(input)

	if string(actual) != expected {
		t.Error("Failed to decrypt single byte XOR. Expected ", expected, " got ", string(actual))
	}
}
