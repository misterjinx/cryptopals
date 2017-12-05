package set1

func repeatingKeyXOR(text string, key []byte) []byte {
	textLength := len(text)
	keyLength := len(key)

	xored := make([]byte, textLength)

	for i := range text {
		xored[i] = text[i] ^ key[i%keyLength]
	}

	return xored
}
