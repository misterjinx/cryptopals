package set1

import (
	"testing"
)

func TestHammingDistance(t *testing.T) {
	s1 := "this is a test"
	s2 := "wokka wokka!!!"

	expected := 37

	// pass the strings as their binary representation
	distance, err := hammingDistance(stringToBinary(s1), stringToBinary(s2))
	if err != nil {
		t.Error("Hamming distance error", err)
	}

	if distance != expected {
		t.Error("Failed to calculate hamming diatance, expected", expected, "got", distance)
	}
}
