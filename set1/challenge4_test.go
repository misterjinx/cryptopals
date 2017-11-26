package set1

import (
	"strings"
	"testing"
)

func TestDetectSingleCharXOR(t *testing.T) {
	expected := "Now that the party is jumping"

	actual, _, _ := detectSingleCharXOR()

	if strings.TrimSpace(string(actual)) != expected {
		t.Error("Failed to detect single char XOR. Expected", expected, "got", actual)
	}
}
