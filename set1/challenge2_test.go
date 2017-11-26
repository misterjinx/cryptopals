package set1

import (
	"encoding/hex"
	"testing"
)

func TestFixedXOR(t *testing.T) {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"
	actual := hex.EncodeToString(fixedXOR(input1, input2))

	if expected != actual {
		t.Error("Failed fixed XOR of ", input1, " and ", input2, ". Expected ", expected, " got ", actual)
	}
}
