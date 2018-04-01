package utils

import (
	"crypto/aes"
	"crypto/rand"
	mrand "math/rand"
	"time"
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

// this is, of course, not secure
func GenerateRandomCharacters(size int) []byte {
	output := make([]byte, size)

	for i := 0; i < size; i++ {
		output[i] = byte(GenerateRandomNumber(33, 126)) // printable ASCII characters, without space
	}

	return output
}

func GenerateRandomNumber(min int, max int) int {
	s1 := mrand.NewSource(time.Now().UnixNano()) // seed
	r1 := mrand.New(s1)

	return r1.Intn(max-min+1) + min
}
