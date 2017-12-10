package set2

/**
 * https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
 *
 * For the moment I don't add padding to plaintexts multiple of block size
 */
func pkcs7padding(plainText []byte, blockSize int) []byte {
	plainTextLength := len(plainText)
	remainder := plainTextLength % blockSize

	if remainder == 0 {
		return plainText
	}

	paddingBytesToAdd := blockSize - remainder

	for i := 0; i < paddingBytesToAdd; i++ {
		plainText = append(plainText, byte(paddingBytesToAdd))
	}

	return plainText
}
