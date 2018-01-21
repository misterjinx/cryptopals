package set2

import (
	"bytes"
	"net/url"
)

const SOME_RANDOM_KEY = "YnUJbbcD2A7ECX6A"
const SOME_RANDOM_IV = "zJyhhydfB0Zi2rrR"

func encryptInputTextCBC(inputText []byte) ([]byte, error) {
	prefix := []byte("comment1=cooking%20MCs;userdata=")
	suffix := []byte(";comment2=%20like%20a%20pound%20of%20bacon")

	var input []byte

	input = append(input, prefix...)
	input = append(input, escapeInput(inputText)...)
	input = append(input, suffix...)

	cipher, err := encryptAesCbcMode(input, []byte(SOME_RANDOM_KEY), []byte(SOME_RANDOM_IV))
	if err != nil {
		return nil, err
	}

	return cipher, nil
}

func decryptCipherTextCBC(cipherText []byte) ([]byte, error) {
	text, err := decryptAesCbcMode(cipherText, []byte(SOME_RANDOM_KEY), []byte(SOME_RANDOM_IV))
	if err != nil {
		return nil, err
	}

	return text, nil
}

func isAdmin(input []byte) bool {
	if bytes.Index(input, []byte(";admin=true;")) == -1 {
		return false
	}

	return true
}

func escapeInput(input []byte) []byte {
	return []byte(url.QueryEscape(string(input)))
}
