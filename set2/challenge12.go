package set2

import (
	"encoding/base64"
	"log"
)

const UNKNOWN_KEY = "QeGK6ThvFTuFa27R"

func encryptionECB(plainText []byte) ([]byte, error) {
	key := []byte(UNKNOWN_KEY)

	var finalPlainText []byte

	finalPlainText = append(finalPlainText, plainText...)

	unknownString, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	if err != nil {
		log.Fatal(err)
	}

	finalPlainText = append(finalPlainText, unknownString...)

	cipherText := make([]byte, len(finalPlainText))

	cipherText, err = aes128ecbEncrypt(finalPlainText, key)
	if err != nil {
		return nil, err
	}

	return cipherText, nil
}
