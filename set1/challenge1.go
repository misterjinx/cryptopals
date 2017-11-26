package set1

import (
	"encoding/base64"
	"encoding/hex"
	"log"
)

func convertHexToBase64(hexString string) string {
	decoded := decodeHex(hexString)
	return base64.StdEncoding.EncodeToString(decoded)
}

func decodeHex(hexString string) []byte {
	decoded, err := hex.DecodeString(hexString)
	if err != nil {
		log.Fatal(err)
	}

	return decoded
}
