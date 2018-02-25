package set3

import (
	"bufio"
	"bytes"
	"cryptopals/utils"
	"encoding/base64"
	"math"
	"os"
	"testing"
)

func TestBreakFixedNonceCTRStatistically(t *testing.T) {
	file, err := os.Open("./20.txt")
	if err != nil {
		t.Error(err)
	}
	defer file.Close()

	var minLength int
	var plainTexts [][]byte

	minLength = math.MaxInt32

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		plainText, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			t.Error("Failed to base64 decode string", err)
		}

		curLength := len(plainText)
		if curLength < minLength {
			minLength = curLength
		}

		plainTexts = append(plainTexts, plainText)
	}

	if err := scanner.Err(); err != nil {
		t.Error(err)
	}

	key, err := utils.GenerateRandomAesKey()
	if err != nil {
		t.Error("Failed to generate random AES key:", err)
	}
	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 0}

	cipherTexts := getCTRCipherTexts(plainTexts, key, nonce)

	truncatedCipherTexts := truncateCipherTextsToCommonLength(cipherTexts, minLength)

	decrypted := breakFixedNonceCTRStatistically(truncatedCipherTexts, minLength)

	expected, err := os.Open("./20.out")
	if err != nil {
		t.Error(err)
	}
	defer expected.Close()

	scanner = bufio.NewScanner(expected)

	i := 0
	for scanner.Scan() {
		expectedText, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			t.Error("Failed to base64 decode expected string", err)
		}

		if !bytes.Equal(expectedText, decrypted[i]) {
			t.Error("Failed to decrypt line ", i)
		}

		i++
	}

	if err := scanner.Err(); err != nil {
		t.Error(err)
	}
}
