package set1

import "log"

func fixedXOR(buf1 string, buf2 string) []byte {
	if len(buf1) != len(buf2) {
		log.Fatal("Buffers have different lengths")
	}

	buf1Decoded := decodeHex(buf1)
	buf2Decoded := decodeHex(buf2)

	xored := make([]byte, len(buf1Decoded))

	for i := range buf1Decoded {
		xored[i] = buf1Decoded[i] ^ buf2Decoded[i]
	}

	return xored
}
