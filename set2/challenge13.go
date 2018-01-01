package set2

import (
	"cryptopals/set1"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

func parseKeyValueParams(qs string) map[string]interface{} {
	pairs := strings.Split(qs, "&")
	params := make(map[string]interface{}, len(pairs))

	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		key := kv[0]
		value := kv[1]

		params[key] = value
	}

	return params
}

func profileFor(email []byte) ([]byte, error) {
	re := regexp.MustCompile("^[^\\s@]+@[^\\s@]+\\.[^\\s@=&]+$")
	matched := re.Match(email)
	if matched == false {
		return nil, errors.New("Invalid email address provided")
	}

	qs := fmt.Sprintf("email=%s&uid=10&role=user", email)

	return []byte(qs), nil
}

func encryptUserProfileECB(plainTextProfile []byte, key []byte) ([]byte, error) {
	cipher, err := aes128ecbEncrypt(plainTextProfile, key)
	if err != nil {
		return nil, err
	}

	return cipher, nil
}

func decryptUserProfileECB(cipherTextProfile []byte, key []byte) ([]byte, error) {
	profile, err := set1.Aes128ecbDecrypt(cipherTextProfile, key)
	if err != nil {
		return nil, err
	}

	return profile, nil
}
