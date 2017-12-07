package set1

import "bytes"

func detectAes128EcbEncryption(cipherText []byte) bool {
	blockSize := 16

	var blocks [][]byte

	for i := 0; i < len(cipherText); i += blockSize {
		currentBlock := cipherText[i : i+blockSize]

		for _, block := range blocks {
			if bytes.Equal(block, currentBlock) {
				return true
			}
		}

		// not found
		blocks = append(blocks, currentBlock)
	}

	return false
}
