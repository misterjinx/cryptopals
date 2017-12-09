package set2

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"testing"
)

func TestEncryptAndDecryptAesCbcMode(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")       // 16 bytes
	iv := []byte("abcdefghijklmnop")        // 16 bytes
	plainText := []byte("testTESTtestTEST") // 16 bytes

	cipherText, err := encryptAesCbcMode(plainText, key, iv)
	if err != nil {
		t.Error("Failed to encrypt AES CBC mode, got error:", err)
	}

	result, _ := decryptAesCbcMode(cipherText, key, iv)

	if !bytes.Equal(result, plainText) {
		t.Error("Failed to test AES CBC encrypt and decrypt")
	}
}

func TestDecryptAesCbcModeAgainstProvidedFile(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	iv := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	content, err := ioutil.ReadFile("./10.txt")
	if err != nil {
		log.Fatal(err)
	}

	cipherText, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		log.Fatal(err)
	}

	plainText, _ := decryptAesCbcMode(cipherText, key, iv)

	expected, err := ioutil.ReadFile("./10.out")
	if err != nil {
		log.Fatal(err)
	}

	if !bytes.Equal(plainText, expected) {
		t.Error("Failed to decrypt AES CBC mode")
	}
}
