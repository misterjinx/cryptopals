package set1

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"testing"
)

func TestAes128EcbDecrypt(t *testing.T) {
	key := "YELLOW SUBMARINE"
	content, err := ioutil.ReadFile("./7.txt")
	if err != nil {
		log.Fatal(err)
	}

	decodedContent, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		log.Fatal(err)
	}

	expected, err := ioutil.ReadFile("./7.out")
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := Aes128ecbDecrypt(decodedContent, []byte(key))
	if err != nil {
		log.Fatal(err)
	}

	if !bytes.Equal(expected, plaintext) {
		t.Error("Failed to decrypt AES 128 ECB cipher")
	}
}
