package set2

/**
 * https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
 */
func pkcs7padding(plainText []byte, blockSize int) []byte {
	plainTextLength := len(plainText)
	remainder := plainTextLength % blockSize

	var paddingBytesToAdd int

	if remainder == 0 {
		paddingBytesToAdd = blockSize
	} else {
		paddingBytesToAdd = blockSize - remainder
	}

	for i := 0; i < paddingBytesToAdd; i++ {
		plainText = append(plainText, byte(paddingBytesToAdd))
	}

	return plainText
}
