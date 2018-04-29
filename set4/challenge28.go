package set4

import (
	"encoding/binary"
	"fmt"
)

/**
 * Based on the pseudocode from the wikipedia page:
 * https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
 *
 * And the excellent FIPS 180-1 (Secure Hash Standard) guide:
 * http://www.umich.edu/~x509/ssleay/fip180/fip180-1.htm
 *
 * Other useful information regarding the algorithm:
 * https://www.ietf.org/rfc/rfc3174.txt
 * http://www.herongyang.com/Cryptography/SHA1-Message-Digest-Algorithm-Overview.html
 */

const digestSize = 20 // bytes
const blockSize = 64  // bytes

const (
	h0 uint32 = 0x67452301
	h1 uint32 = 0xEFCDAB89
	h2 uint32 = 0x98BADCFE
	h3 uint32 = 0x10325476
	h4 uint32 = 0xC3D2E1F0

	k1 uint32 = 0x5A827999
	k2 uint32 = 0x6ED9EBA1
	k3 uint32 = 0x8F1BBCDC
	k4 uint32 = 0xCA62C1D6
)

func SHA1Digest(input []byte) [digestSize]byte {
	/* Initial state */
	h := [5]uint32{h0, h1, h2, h3, h4}

	l := len(input)
	ml := l * 8 /* message length in bits */

	/* Pre-processing */

	/* append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits. */
	input = append(input, byte(0x80))

	/* append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512) */
	paddingCount := 64 - (l+9)%64
	for i := 0; i < paddingCount; i++ {
		input = append(input, byte(0x00))
	}

	/* append ml, the original message length, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits. */
	msgLengthBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(msgLengthBytes, uint64(ml))
	input = append(input, msgLengthBytes...)

	/* Process the message in successive 512-bit chunks: */

	l = len(input) /* length is different after the padding process */
	/* break message into 512-bit chunks */
	for i := 0; i < l; i += blockSize { // 512 bits = 64 bytes
		chunk := input[i : i+blockSize]

		/* Prepare words slice */
		w := make([]uint32, 80)

		/* break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15 */
		for j := 0; j < 16; j++ {
			word := chunk[j*4 : j*4+4] // each 32 bit equals 4 bytes of the chunk (64 bytes / 4 bytes = 16)
			w[j] = binary.BigEndian.Uint32(word)
		}

		/* Extend the sixteen 32-bit words into eighty 32-bit words: */
		for j := 16; j < 80; j++ {
			temp := w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]
			w[j] = leftRotate(temp, 1)
		}

		/* Initialize hash value for this chunk: */
		a := h[0]
		b := h[1]
		c := h[2]
		d := h[3]
		e := h[4]

		/* Main loop: */
		var f, k uint32
		for t := 0; t < 80; t++ {
			if t >= 0 && t <= 19 {
				f = (b & c) | ((^b) & d)
				k = k1
			} else if t >= 20 && t <= 39 {
				f = b ^ c ^ d
				k = k2
			} else if t >= 40 && t <= 59 {
				f = (b & c) | (b & d) | (c & d)
				k = k3
			} else if t >= 60 && t <= 79 {
				f = b ^ c ^ d
				k = k4
			}

			temp := leftRotate(a, 5) + f + e + k + w[t]
			e = d
			d = c
			c = leftRotate(b, 30)
			b = a
			a = temp
		}

		/* Add this chunk's hash to result so far: */
		h[0] = h[0] + a
		h[1] = h[1] + b
		h[2] = h[2] + c
		h[3] = h[3] + d
		h[4] = h[4] + e
	}

	/* Produce the final hash value (big-endian) as a 160-bit number (32 bit * 5 = 160 bit): */
	// hh := (h[0] << 128) | (h[1] << 96) | (h[2] << 64) | (h[3] << 32) | h[4]

	var digest [digestSize]byte // digest size is 20 bytes

	binary.BigEndian.PutUint32(digest[0:4], h[0])
	binary.BigEndian.PutUint32(digest[4:8], h[1])
	binary.BigEndian.PutUint32(digest[8:12], h[2])
	binary.BigEndian.PutUint32(digest[12:16], h[3])
	binary.BigEndian.PutUint32(digest[16:20], h[4])

	return digest
}

func SHA1HexDigest(input []byte) string {
	var sum string

	digest := SHA1Digest(input)
	for _, b := range digest {
		sum += fmt.Sprintf("%02x", b)
	}

	return sum
}

func leftRotate(word uint32, bits uint32) uint32 {
	return (((word) << (bits)) | ((word) >> (32 - (bits))))
}

func SHA1SecretPrefixMAC(key []byte, message []byte) []byte {
	digest := SHA1Digest(append(key, message...))
	return digest[:] // to get rid of the [20]byte type that is returned by SHA1Digest, thus allowing these values to be used with bytes.Equal
}
