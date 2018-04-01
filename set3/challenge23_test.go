package set3

import (
	"testing"
)

func TestCloneMT19937(t *testing.T) {
	seed := getMT19937Seed()

	mt := NewMT19937(seed)

	clone := cloneMT19937(mt)

	for i := 0; i < 10000; i++ {
		if mt.ExtractNumber() != clone.ExtractNumber() {
			t.Error("Failed to clone MT19937")
			break
		}
	}
}
