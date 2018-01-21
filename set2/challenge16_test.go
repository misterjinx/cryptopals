package set2

import "testing"

func TestCBCBitflippingAttack(t *testing.T) {
	cipherText, err := encryptInputTextCBC([]byte("1admin2true"))
	if err != nil {
		t.Error("Failed to encrypt input text CBC")
	}

	// By passing the "1admin2true" as input the plain text after
	// decryption will be:

	// comment1=cooking%20MCs;userdata=1admin2true;comment2=%20like%20a%20pound%20of%20bacon

	// The goal is to obtain ";admin=true;" inside this plain text.

	// Splitting the plain text in blocks we get the following chunks:

	// B0: comment1=cooking
	// B1: %20MCs;userdata=
	// B2: 1admin2true;comm
	// B3: ent2=%20like%20a
	// B4: %20pound%20of%20
	// B5: bacon

	// Cipher text will be something like this (pkcs7 padded):

	// C0: xxxxxxxxxxxxxxxx
	// C1: yyyyyyyyyyyyyyyy
	// C2: zzzzzzzzzzzzzzzz
	// C3: ssssssssssssssss
	// C4: tttttttttttttttt
	// C5: wwwwwwwwwwwwwwww

	// Looking at the plaintext blocks we can see that our controlled
	// input is inside block 2 (B2).

	// When decrypting in CBC mode[1], each block is XORed with the
	// cipher text of the previous block. One-bit change to the cipher
	// text causes complete corruption of the corresponding plaintext
	// block, BUT it inverts the corresponding bit in the following
	// plaintext block, the rest of the blocks remaining intact.

	// This means that in order to alter the B2 block of the plain text,
	// we have to change the previous ciphered block, C1, so that after
	// the XOR operation the plain text block B2, will have some of the
	// bytes modified to our need.

	// In this example, byte 0 and byte 6 of C1 ciphertext have to be
	// crafted so that B2's plaintext bytes at the same positions are
	// modified to our intended bytes.

	// We can also make use of the XOR operation for our goal. For
	// instance, to change the "1" character to a semicolon:

	// C1[0] = C1[0] ^ byte("1") ^ byte(";")

	// After that, when C1 is XORed with B2 to obtain the plaintext, the
	// following will happen:

	// C1[0] ^ B2[0] = C1[0] ^ byte("1") ^ byte(";") ^ byte("1") = C1[0] ^ byte(";")

	// byte(1) ^ byte(1) cancel out due to XOR, thus resulting in our
	// intented chracter inserted in the plaintext at the position we
	// needed.

	// [1] https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC))

	cipherText[16] = cipherText[16] ^ []byte("1")[0] ^ []byte(";")[0]
	cipherText[22] = cipherText[22] ^ []byte("2")[0] ^ []byte("=")[0]

	inputText, err := decryptCipherTextCBC(cipherText)
	if err != nil {
		t.Error("Failed to decrypt cipher text CBC")
	}

	if !isAdmin(inputText) {
		t.Error("Failed to create admin using CBC bit flipping")
	}
}
