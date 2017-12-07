package set2

const PKCS7_PAD = byte(0x04)

func pkcs7padding(plainText []byte, blockSize int) []byte {
	plainTextLength := len(plainText)
	if plainTextLength >= blockSize {
		return plainText
	}

	for i := plainTextLength; i < blockSize; i++ {
		plainText = append(plainText, PKCS7_PAD)
	}

	return plainText
}
