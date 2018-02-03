package utils

import (
	"crypto/aes"
	"crypto/rand"
)

func GenerateRandomAesKey() ([]byte, error) {
	key, err := GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func GenerateRandomBytes(size int) ([]byte, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}
