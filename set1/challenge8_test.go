package set1

import (
	"bufio"
	"encoding/base64"
	"log"
	"os"
	"testing"
)

func TestDetectAes128EcbEncryption(t *testing.T) {
	expected := "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"

	file, err := os.Open("./8.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	actual := ""

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		decodedContent, err := base64.StdEncoding.DecodeString(string(line))
		if err != nil {
			log.Fatal(err)
		}

		if DetectAes128EcbEncryption(decodedContent) {
			actual = string(line)
			break
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	if expected != actual {
		t.Error("Failed to detect AES ECB encrypted cipher text")
	}
}
