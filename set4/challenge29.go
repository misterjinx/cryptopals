package set4

import "encoding/binary"

/**
 * Resources on hash length extension attack:
 *
 * http://netifera.com/research/flickr_api_signature_forgery.pdf
 * https://en.wikipedia.org/wiki/Length_extension_attack
 * https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
 * https://www.whitehatsec.com/blog/hash-length-extension-attacks/
 * https://web.archive.org/web/20120826010038/http://www.vnsecurity.net/2010/03/codegate_challenge15_sha1_padding_attack/
 */
func createSHA1SecretPrefixMACCraftedInput(initialState []byte, message []byte, extension []byte, secretPrefixLength int) ([]byte, []byte) {
	glue := createSHA1GluePadding(len(message) + secretPrefixLength)

	var craftedInput []byte
	craftedInput = append(craftedInput, message...)
	craftedInput = append(craftedInput, glue...)

	sha1 := NewSHA1()
	sha1.h[0] = binary.BigEndian.Uint32(initialState[0:4])   // 0xdea635c7
	sha1.h[1] = binary.BigEndian.Uint32(initialState[4:8])   // 0x8fe5c9f8
	sha1.h[2] = binary.BigEndian.Uint32(initialState[8:12])  // 0x152407d3
	sha1.h[3] = binary.BigEndian.Uint32(initialState[12:16]) // 0x698a3943
	sha1.h[4] = binary.BigEndian.Uint32(initialState[16:20]) // 0x62967c89

	sha1.l = len(craftedInput) + secretPrefixLength // normally the length of the secret is not known, but this is not an issue because it can be found by trying multiple values until the final hash matches

	craftedHash := sha1.Digest(extension)

	craftedInput = append(craftedInput, extension...)

	return craftedInput, craftedHash[:]
}

func createSHA1GluePadding(length int) []byte {
	glue := createGluePadding(length)

	appendBigEndianMessageLength(&glue, length)

	return glue
}

func createGluePadding(length int) []byte {
	glue := []byte{0x80} // padding

	/* append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512) */
	paddingCount := 64 - (length+9)%64
	for i := 0; i < paddingCount; i++ {
		glue = append(glue, byte(0x00))
	}

	return glue
}

func appendBigEndianMessageLength(glue *[]byte, length int) {
	msgLengthBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(msgLengthBytes, uint64(length*8))

	*glue = append(*glue, msgLengthBytes...)
}
