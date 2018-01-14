package set2

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"errors"
)

const THIS_UNKNOWN_KEY = "@QeGK6Th*vFTua27"
const RANDOM_PREFIX = "1&dpF%GgZ$lQ"

func randomPrefixEncryptionECB(plainText []byte) ([]byte, error) {
	key := []byte(THIS_UNKNOWN_KEY)
	prefix := []byte(RANDOM_PREFIX)

	var finalPlainText []byte

	finalPlainText = append(finalPlainText, prefix...)
	finalPlainText = append(finalPlainText, plainText...)

	unknownText, err := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	if err != nil {
		return nil, err
	}

	finalPlainText = append(finalPlainText, unknownText...)

	cipherText := make([]byte, len(finalPlainText))

	cipherText, err = aes128ecbEncrypt(finalPlainText, key)
	if err != nil {
		return nil, err
	}

	return cipherText, nil
}

/**
 * Let's say the block size is 8 bytes. If the added prefix is 'random'
 * the trick is to send an input that will fill not only the block with
 * the prefix, but also the next block, so that you will have a whole
 * block available to send crafted input (like there would be no prefix
 * at all). For this particular example your crafted input should have
 * a size of 2 * block_size - len(prefix) - 1. As you find the unknown
 * text, char by char, the new crafted input size should decrease by 1,
 * and each char found must be appended to the crafted input.
 *
 * +-------------------------------+ +-------------------------------+
 * | R | A | N | D | O | M | X | X | | X | X | X | X | X | X | X | ? |
 * +-------------------------------+ +-------------------------------+
 */
func byteAtATimeECBDecryptionHarder() ([]byte, error) {
	// determine the size of the ciphertext
	a, _ := randomPrefixEncryptionECB([]byte("A"))
	size := len(a)

	prefixSize, err := determinePrefixSize()
	if err != nil {
		return nil, err
	}

	if prefixSize == -1 {
		return nil, errors.New("Couldn't determine prefix size")
	}

	var decrypted []byte

	for i := size - 1; i > prefixSize; i-- {
		input := bytes.Repeat([]byte("A"), i-prefixSize)

		output, err := randomPrefixEncryptionECB(input)
		if err != nil {
			return nil, err
		}

		craftedInput := make([]byte, size)
		copy(craftedInput[prefixSize:], input)
		decryptedLength := len(decrypted)
		if decryptedLength > 0 {
			j := prefixSize + len(input)
			copy(craftedInput[j:j+decryptedLength], decrypted)
		}

		for c := 0; c <= 255; c++ { // ascii characters
			char := byte(c)
			craftedInput[size-1] = char

			encrypted, err := randomPrefixEncryptionECB(craftedInput[prefixSize:])
			if err != nil {
				return nil, err
			}

			if bytes.Equal(encrypted[16:size], output[16:size]) {
				decrypted = append(decrypted, char)
				break
			}
		}
	}

	return decrypted, nil
}

func determinePrefixSize() (int, error) {
	prefixSize := -1 // in case not found or error

	blockWithPrefixSize := 0
	input := bytes.Repeat([]byte("A"), aes.BlockSize)

	// TODO: funny thing, if the used prefix consists only of the char
	// "A" (eg. "A", "AA", "AAA", etc.) - the char that I also use to
	// send input to the encryption function -, the prefix cannot be
	// found because it will interfere with the crafted input. I should
	// probably think of a better way to avoid this.

	// If an input with the length of 3 blocksizes is used, the
	// returned ciphertext will have 2 blocks with the same content.
	// When the 2 blocks are found, the size of the block that contains
	// the prefix is also found.
	enc, err := randomPrefixEncryptionECB(bytes.Repeat(input, 3))
	if err != nil {
		return prefixSize, err
	}

	for i := 0; i < len(enc)-aes.BlockSize; i++ {
		j := i + aes.BlockSize
		if bytes.Equal(enc[i:j], enc[j:j+aes.BlockSize]) {
			blockWithPrefixSize = i
			break
		}
	}

	// After the size of the block (this is actually a multiple of the
	// aes blocksize since the prefix can be longer than one block) that
	// contains the prefix was found, start encrypting a multiple of one
	// byte input and check if two consecutive returned encryptions with
	// the size of the block that contains the prefix are the same. When
	// the two blocks have the same bytes it means the actual size of
	// the prefix was found.
	if blockWithPrefixSize > 0 {
		var prevBlock []byte
		for i := 1; i <= blockWithPrefixSize; i++ {
			enc, _ := randomPrefixEncryptionECB(bytes.Repeat([]byte("A"), i))
			curBlock := enc[:blockWithPrefixSize]

			if prevBlock != nil && bytes.Equal(prevBlock, curBlock) {
				prefixSize = blockWithPrefixSize - (i - 1)
				break
			}

			prevBlock = curBlock
		}
	}

	return prefixSize, nil
}
