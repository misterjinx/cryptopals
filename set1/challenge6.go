package set1

import (
	"errors"
	"fmt"
	"math"
)

func hammingDistance(s1 []byte, s2 []byte) (int, error) {
	if len(s1) != len(s2) {
		return -1, errors.New("Undefined for strings of unequal length")
	}

	s1Binary := bytesToBinary(s1)
	s2Binary := bytesToBinary(s2)

	distance := 0

	for i := range s1Binary {
		if s1Binary[i] != s2Binary[i] {
			distance += 1
		}
	}

	return distance, nil
}

func bytesToBinary(s []byte) string {
	result := ""
	for _, c := range s {
		result = fmt.Sprintf("%s%.8b", result, c)
	}
	return result
}

func breakVigenere(text []byte) ([]byte, []byte) {
	keysize := detectVigenereKeySize(text)

	blocks := ChunkArray(text, keysize)

	var transpose [][]byte

	for i := 0; i < keysize; i++ {
		var block []byte
		for j := 0; j < len(blocks); j++ {
			if i < len(blocks[j]) {
				block = append(block, blocks[j][i])
			}
		}

		transpose = append(transpose, block)
	}

	var finalKey []byte

	for _, block := range transpose {
		_, blockKey, _ := decryptSingleByteXOR(block)
		finalKey = append(finalKey, blockKey)
	}

	result := repeatingKeyXOR(string(text), finalKey)

	return result, finalKey
}

/**
 * Algorithm from http://cryptopals.com/sets/1/challenges/6
 *
 * 1. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the
 *    second KEYSIZE worth of bytes, and find the edit distance between
 *    them. Normalize this result by dividing by KEYSIZE.
 * 2. The KEYSIZE with the smallest normalized edit distance is probably
 *    the key. You could proceed perhaps with the smallest 2-3 KEYSIZE
 *    values. Or take 4 KEYSIZE blocks instead of 2 and average the
 *    distances.
 * 3. Now that you probably know the KEYSIZE: break the ciphertext into
 *    blocks of KEYSIZE length.
 * 4. Now transpose the blocks: make a block that is the first byte of
 *    every block, and a block that is the second byte of every block,
 *    and so on.
 * 5. Solve each block as if it was single-character XOR. You already
 *    have code to do this.
 * 6. For each block, the single-byte XOR key that produces the best
 *    looking histogram is the repeating-key XOR key byte for that block.
 *    Put them together and you have the key.
 */
func detectVigenereKeySize(text []byte) int {
	var detectedKeySize int
	var smallestEditDistance float32
	smallestEditDistance = math.MaxFloat32

	startAt := 2
	endAt := 40

	for keysize := startAt; keysize <= endAt; keysize++ {
		// 4 keysize length for each block (the wording from step 2 was not very clear about this)
		blocklength := keysize * 4

		firstWorth := text[0:blocklength]
		secondWorth := text[blocklength : blocklength*2]

		editDistance, _ := hammingDistance(firstWorth, secondWorth)
		normalizedEditDistance := float32(editDistance) / float32(keysize)

		if normalizedEditDistance < smallestEditDistance {
			smallestEditDistance = normalizedEditDistance
			detectedKeySize = keysize
		}
	}

	return detectedKeySize
}

func ChunkArray(array []byte, size int) [][]byte {
	var chunks [][]byte
	var chunk []byte

	for len(array) >= size {
		chunk, array = array[:size], array[size:]
		chunks = append(chunks, chunk)
	}

	if len(array) > 0 {
		chunks = append(chunks, array)
	}

	return chunks
}
