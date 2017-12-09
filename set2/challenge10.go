package set2

import (
	"crypto/aes"
	"cryptopals/set1"
	"errors"
)

/**
 * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
 */
func encryptAesCbcMode(plainText []byte, key []byte, iv []byte) ([]byte, error) {
	if len(plainText)%aes.BlockSize != 0 {
		return nil, errors.New("Plaintext is not multiple of block size")
	}

	var cipherText []byte

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plainTextLength := len(plainText)
	blockSize := cipher.BlockSize()

	var previousBlock []byte

	for i := 0; i < plainTextLength; i += blockSize {
		if i == 0 {
			previousBlock = iv
		} else {
			previousBlock = cipherText[i-blockSize : i]
		}

		xored := set1.FixedXOR(previousBlock, plainText[i:i+blockSize])

		encryptedBlock := make([]byte, blockSize)
		cipher.Encrypt(encryptedBlock, xored)

		cipherText = append(cipherText, encryptedBlock...)
	}

	return cipherText, nil
}

/**
 * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
 */
func decryptAesCbcMode(cipherText []byte, key []byte, iv []byte) ([]byte, error) {
	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("Ciphertext is shorter than block size")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var plainText []byte

	cipherTextLength := len(cipherText)
	blockSize := cipher.BlockSize()

	var previousBlock []byte
	for i := 0; i < cipherTextLength; i += blockSize {
		if i == 0 {
			previousBlock = iv
		} else {
			previousBlock = cipherText[i-blockSize : i]
		}

		decrytedBlock := make([]byte, blockSize)

		cipher.Decrypt(decrytedBlock, cipherText[i:i+blockSize])
		xored := set1.FixedXOR(previousBlock, decrytedBlock)

		plainText = append(plainText, xored...)
	}

	return plainText, nil
}
