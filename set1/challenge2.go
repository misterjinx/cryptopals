package set1

import "log"

func FixedXOR(buf1 []byte, buf2 []byte) []byte {
	if len(buf1) != len(buf2) {
		log.Fatal("Buffers have different lengths")
	}

	xored := make([]byte, len(buf1))

	for i := range buf1 {
		xored[i] = buf1[i] ^ buf2[i]
	}

	return xored
}
