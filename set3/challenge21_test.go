package set3

import (
	"testing"
	"time"
)

func TestMT19937(t *testing.T) {
	mt := newMT19937(uint32(time.Now().Unix()))
	if mt.ExtractNumber() < 0 {
		t.Error("Failed to generate a new number with MT19937")
	}
}
