package set1

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"testing"
)

func TestAes128EcbDecrypt(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	content, err := ioutil.ReadFile("./7.txt")
	if err != nil {
		t.Fatal(err)
	}

	decodedContent, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		t.Fatal(err)
	}

	expectedEncoded, err := ioutil.ReadFile("./7.out")
	if err != nil {
		t.Fatal("Failed to read base64 encoded output: ", err)
	}

	expected, err := base64.StdEncoding.DecodeString(string(expectedEncoded))
	if err != nil {
		t.Fatal("Failed to base64 decode expected output: ", err)
	}

	plaintext, err := Aes128ecbDecrypt(decodedContent, key)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(expected, plaintext) {
		t.Error("Failed to decrypt AES 128 ECB cipher")
	}
}
