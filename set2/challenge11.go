package set2

import (
	"crypto/aes"
	"cryptopals/utils"
)

func encryptionOracle(plainText []byte) ([]byte, error, string) {
	var mode string

	key, _ := utils.GenerateRandomAesKey()

	beforeSize := utils.GenerateRandomNumber(5, 10)
	bytesBefore, err := utils.GenerateRandomBytes(beforeSize)
	if err != nil {
		return nil, err, mode
	}

	afterSize := utils.GenerateRandomNumber(5, 10)
	bytesAfter, err := utils.GenerateRandomBytes(afterSize)
	if err != nil {
		return nil, err, mode
	}

	var finalPlainText []byte
	finalPlainText = append(finalPlainText, bytesBefore...)
	finalPlainText = append(finalPlainText, plainText...)
	finalPlainText = append(finalPlainText, bytesAfter...)

	cipherText := make([]byte, len(finalPlainText))

	choice := utils.GenerateRandomNumber(0, 1) // 0 or 1
	if choice == 0 {
		// do ecb
		mode = "ecb"

		cipherText, err = aes128ecbEncrypt(finalPlainText, key)
		if err != nil {
			return nil, err, mode
		}
	} else {
		// do cbc
		mode = "cbc"

		iv, err := utils.GenerateRandomBytes(16)
		if err != nil {
			return nil, err, mode
		}

		cipherText, err = EncryptAesCbcMode(finalPlainText, key, iv)
		if err != nil {
			return nil, err, mode
		}
	}

	return cipherText, nil, mode
}

/**
 * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB
 *
 * The message is divided into blocks, and each block is encrypted
 * separately.
 */
func aes128ecbEncrypt(plainText []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var cipherText []byte

	plainTextLength := len(plainText)
	blockSize := cipher.BlockSize()

	if plainTextLength%blockSize != 0 {
		// apply pkcs7 padding
		plainText = pkcs7padding(plainText, blockSize)
	}

	for i := 0; i < plainTextLength; i += blockSize {
		encrytedBlock := make([]byte, blockSize)

		cipher.Encrypt(encrytedBlock, plainText[i:i+blockSize])
		cipherText = append(cipherText, encrytedBlock...)
	}

	return cipherText, nil
}
