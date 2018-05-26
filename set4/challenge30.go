package set4

import (
	"encoding/binary"
	"fmt"
)

/**
 * Official paper for MD4 https://tools.ietf.org/html/rfc1320
 *
 * The block processing of the following version is based on the D
 * implementation from https://rosettacode.org/wiki/MD4#D
 *
 * ATTENTION!!!
 * MD4 is using Little-Endian notation
 */

const MD4DigestSize = 16 // bytes
const MD4BlockSize = 64  // bytes

const (
	a uint32 = 0x67452301
	b uint32 = 0xefcdab89
	c uint32 = 0x98badcfe
	d uint32 = 0x10325476
)

type MD4 struct {
	state [4]uint32 // registers
	count int       // input length; declared because it's useful when doing the length extension attack
}

func (hash *MD4) Init() {
	hash.count = 0

	/* Initial state */
	hash.state = [4]uint32{a, b, c, d}
}

func (hash *MD4) Digest(input []byte) [MD4DigestSize]byte {
	hash.count += len(input)
	ml := hash.count * 8 /* message length in bits */

	/* Pre-processing */

	/* append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits. */
	input = append(input, byte(0x80))

	/* append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512) */
	paddingCount := 64 - (hash.count+9)%64
	for i := 0; i < paddingCount; i++ {
		input = append(input, byte(0x00))
	}

	/* append ml, the original message length, as a 64-bit little-endian integer. Thus, the total length is a multiple of 512 bits. */
	msgLengthBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(msgLengthBytes, uint64(ml))
	input = append(input, msgLengthBytes...)

	/* Process the message in successive 512-bit chunks: */

	nl := len(input) /* length is different after the padding process */

	/* break message into 512-bit chunks */
	for i := 0; i < nl; i += MD4BlockSize { // 512 bits = 64 bytes
		chunk := input[i : i+MD4BlockSize]

		/* Prepare words slice */
		var w [16]uint32

		/* break chunk into sixteen 32-bit little-endian words w[i], 0 ≤ i ≤ 15 */
		for j := 0; j < 16; j++ {
			word := chunk[j*4 : j*4+4] // each 32 bit equals 4 bytes of the chunk (64 bytes / 4 bytes = 16)
			w[j] = binary.LittleEndian.Uint32(word)
		}

		a := hash.state[0]
		b := hash.state[1]
		c := hash.state[2]
		d := hash.state[3]

		for _, i := range [4]uint8{0, 4, 8, 12} {
			a = leftRotate(a+f(b, c, d)+w[i+0], 3)
			d = leftRotate(d+f(a, b, c)+w[i+1], 7)
			c = leftRotate(c+f(d, a, b)+w[i+2], 11)
			b = leftRotate(b+f(c, d, a)+w[i+3], 19)
		}

		for _, i := range [4]uint8{0, 1, 2, 3} {
			a = leftRotate(a+g(b, c, d)+w[i+0]+0x5a827999, 3)
			d = leftRotate(d+g(a, b, c)+w[i+4]+0x5a827999, 5)
			c = leftRotate(c+g(d, a, b)+w[i+8]+0x5a827999, 9)
			b = leftRotate(b+g(c, d, a)+w[i+12]+0x5a827999, 13)
		}

		for _, i := range [4]uint8{0, 2, 1, 3} {
			a = leftRotate(a+h(b, c, d)+w[i+0]+0x6ed9eba1, 3)
			d = leftRotate(d+h(a, b, c)+w[i+8]+0x6ed9eba1, 9)
			c = leftRotate(c+h(d, a, b)+w[i+4]+0x6ed9eba1, 11)
			b = leftRotate(b+h(c, d, a)+w[i+12]+0x6ed9eba1, 15)
		}

		/* Add this chunk's hash to result so far: */
		hash.state[0] += a
		hash.state[1] += b
		hash.state[2] += c
		hash.state[3] += d
	}

	var digest [MD4DigestSize]byte // digest size is 16 bytes

	binary.LittleEndian.PutUint32(digest[0:4], hash.state[0])
	binary.LittleEndian.PutUint32(digest[4:8], hash.state[1])
	binary.LittleEndian.PutUint32(digest[8:12], hash.state[2])
	binary.LittleEndian.PutUint32(digest[12:16], hash.state[3])

	return digest
}

func (hash *MD4) HexDigest(input []byte) string {
	var sum string

	digest := hash.Digest(input)
	for _, b := range digest {
		sum += fmt.Sprintf("%02x", b)
	}

	return sum
}

func f(x uint32, y uint32, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

func g(x uint32, y uint32, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func h(x uint32, y uint32, z uint32) uint32 {
	return x ^ y ^ z
}

func NewMD4() *MD4 {
	hash := &MD4{}
	hash.Init()

	return hash
}

func MD4SecretPrefixMAC(key []byte, message []byte) []byte {
	hash := NewMD4()

	digest := hash.Digest(append(key, message...))
	return digest[:] // to get rid of the [16]byte type that is returned by MD4Digest, thus allowing these values to be used with bytes.Equal
}

func createMD4SecretPrefixMACCraftedInput(initialState []byte, message []byte, extension []byte, secretPrefixLength int) ([]byte, []byte) {
	glue := createMD4GluePadding(len(message) + secretPrefixLength)

	var craftedInput []byte
	craftedInput = append(craftedInput, message...)
	craftedInput = append(craftedInput, glue...)

	md4 := NewMD4()
	md4.state[0] = binary.LittleEndian.Uint32(initialState[0:4])
	md4.state[1] = binary.LittleEndian.Uint32(initialState[4:8])
	md4.state[2] = binary.LittleEndian.Uint32(initialState[8:12])
	md4.state[3] = binary.LittleEndian.Uint32(initialState[12:16])

	md4.count = len(craftedInput) + secretPrefixLength // normally the length of the secret is not known, but this is not an issue because it can be found by trying multiple values until the final hash matches

	craftedHash := md4.Digest(extension)

	craftedInput = append(craftedInput, extension...)

	return craftedInput, craftedHash[:]
}

func createMD4GluePadding(length int) []byte {
	glue := createGluePadding(length)

	appendLittleEndianMessageLength(&glue, length)

	return glue
}

func appendLittleEndianMessageLength(glue *[]byte, length int) {
	msgLengthBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(msgLengthBytes, uint64(length*8))

	*glue = append(*glue, msgLengthBytes...)
}
