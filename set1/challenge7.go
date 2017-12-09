package set1

import (
	"crypto/aes"
)

/**
 * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB
 *
 * The message is divided into blocks, and each block is encrypted
 * separately. Each encrypted block is decrypted separately by taking
 * corresponding blocks of specific size and decrypting them using the
 * decryption key.
 *
 * @TODO: figure out why decryption using go aes package has 4 EOT
 * characters at the end, while decryption using openssl do not
 */
func aes128ecbDecrypt(cipherText []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var plainText []byte

	cipherLength := len(cipherText)
	blockSize := cipher.BlockSize()

	for i := 0; i < cipherLength; i += blockSize {
		decrytedBlock := make([]byte, blockSize)

		cipher.Decrypt(decrytedBlock, cipherText[i:i+blockSize])
		plainText = append(plainText, decrytedBlock...)
	}

	return plainText, nil
}
