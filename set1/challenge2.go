package set1

func FixedXOR(buf1 []byte, buf2 []byte) []byte {
	if len(buf1) > len(buf2) {
		buf1 = buf1[:len(buf2)]
	}

	xored := make([]byte, len(buf1))

	for i := range buf1 {
		xored[i] = buf1[i] ^ buf2[i]
	}

	return xored
}
