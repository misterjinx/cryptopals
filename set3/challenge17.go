package set3

import (
	"bytes"
	"crypto/aes"
	"cryptopals/set2"
	"encoding/base64"
	"math/rand"
	"time"
)

func encryptCBCString(b64Text string, key []byte, iv []byte) ([]byte, error) {
	text, err := base64.StdEncoding.DecodeString(b64Text)
	if err != nil {
		return nil, err
	}

	cipherText, err := set2.EncryptAesCbcMode(text, key, iv)
	if err != nil {
		return nil, err
	}

	return cipherText, nil
}

/**
 * Returns true if the decrypted text has valid padding, false otherwise.
 */
func paddingOracle(cipherText []byte, key []byte, iv []byte) (bool, error) {
	plainText, err := set2.DecryptAesCbcMode(cipherText, key, iv)
	if err != nil {
		return false, err
	}

	_, err = set2.Pkcs7unpadding(plainText, aes.BlockSize)
	if err != nil {
		return false, nil
	}

	return true, nil
}

func decryptCBCPaddingOracle(cipherText []byte, key []byte, iv []byte) []byte {
	plainText := make([]byte, len(cipherText))

	// Considering how CBC mode decryption works, we need two blocks
	// (the current block and the previous block) in order to decrypt
	// our current block. We make use of the XOR operation that takes
	// place as the final step.
	var c1 []byte
	for i := 0; i < len(cipherText); i += aes.BlockSize {
		if i == 0 {
			c1 = iv
		} else {
			c1 = cipherText[i-aes.BlockSize : i]
		}

		c2 := cipherText[i : i+aes.BlockSize]

		p2 := decryptBlockUsingPaddingOracle(c1, c2, key, iv)

		copy(plainText[i:i+aes.BlockSize], p2)
	}

	return plainText
}

/**
 * https://en.wikipedia.org/wiki/Padding_oracle_attack
 *
 * There are some articles describing in detail this attack:
 * https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth
 * https://grymoire.wordpress.com/2014/12/05/cbc-padding-oracle-attacks-simplified-key-concepts-and-pitfalls/
 *
 * Also the following step by step walkthrough is very helpful:
 * https://blog.skullsecurity.org/2013/a-padding-oracle-example
 *
 * And as always, ilustrations help, the following article has some
 * nice visuals on the subject:
 * https://robertheaton.com/2013/07/29/padding-oracle-attack/
 */
func decryptBlockUsingPaddingOracle(c1 []byte, c2 []byte, key []byte, iv []byte) []byte {
	p2 := make([]byte, aes.BlockSize)

	for i := aes.BlockSize - 1; i >= 0; i-- {
		c1p := bytes.Repeat([]byte{0}, aes.BlockSize)
		paddingByte := byte(aes.BlockSize - i)

		// we compute c1p from the last byte until the current byte
		// eg. when i = 14, we compute c1p[15], when i = 13, we compute
		// c1p[15] and c1p[14] etc.
		for j := aes.BlockSize - 1; j > i; j-- {
			c1p[j] = paddingByte ^ p2[j] ^ c1[j]
		}

		for c := 0; c <= 255; c++ {
			c1p[i] = byte(c)
			v, _ := paddingOracle(append(c1p, c2...), key, iv)
			if v == true {
				p2[i] = paddingByte ^ c1[i] ^ c1p[i]
				break
			}
		}
	}

	return p2
}

func getRandomString() string {
	availableStrings := [10]string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}

	rand.Seed(time.Now().Unix())

	return availableStrings[rand.Intn(len(availableStrings))]
}
