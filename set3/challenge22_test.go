package set3

import (
	"testing"
	"time"
)

func TestCrackMT19937Seed(t *testing.T) {
	seed := uint32(time.Now().UnixNano() / int64(time.Millisecond))

	t.Log("Seed is", seed)

	random := getMT19937RandomNumber(seed)

	t.Log("Random number is", random)

	recoveredSeed := crackMT19937Seed(random)

	t.Log("Recovered seed", recoveredSeed)

	if recoveredSeed != seed {
		t.Error("Failed to crack MT19937 seed")
	}
}
