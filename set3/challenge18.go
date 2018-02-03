package set3

import (
    "crypto/aes"
    "cryptopals/set1"
    "errors"
)

func encryptAesCTRMode(plainText []byte, key []byte, nonce []byte) ([]byte, error) {
    return aesCTRMode(plainText, key, nonce)
}

func decryptAesCTRMode(cipherText []byte, key []byte, nonce []byte) ([]byte, error) {
    return aesCTRMode(cipherText, key, nonce)
}

/**
 * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
 *
 * Counter (CTR) mode works the same for encryption and decryption, the only
 * difference is the input. When encrypting, the input provided must be the
 * plain text, and when performing decryption, the input is the cipher text.
 */
func aesCTRMode(input []byte, key []byte, nonce []byte) ([]byte, error) {
    cipher, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    blockSize := cipher.BlockSize()
    if len(nonce) > blockSize/2 {
        return nil, errors.New("Nonce length is greater than half of the blocksize")
    }

    var output []byte

    inputBlock := make([]byte, blockSize)
    copy(inputBlock, nonce)

    inputLength := len(input)
    for i := 0; i < inputLength; i += blockSize {
        encryptedBlock := make([]byte, blockSize)
        cipher.Encrypt(encryptedBlock, inputBlock)

        j := i+blockSize
        if j > inputLength {
            j = inputLength
        }

        xored := set1.FixedXOR(encryptedBlock, input[i:j])
        output = append(output, xored...)

        // increment counter
        for j := len(nonce); j < blockSize; j++ {
            inputBlock[j] += 1
            if inputBlock[j] != 0 {
                break
            }
        }
    }

    return output, nil
}
