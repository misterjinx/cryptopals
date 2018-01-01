package set2

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestCutAndPasteAttack(t *testing.T) {
	// Our user profile has the following format:
	// email=foo@bar.com&uid=10&role=user

	// In order for this attack to work the 'email=X&uid=10&role=' size
	// must perfectly divide by block size. So the chosen email must fit
	// in 32 bytes for the current scenario.

	// For testing purpuses let's use the email address 'foo@bar.comma'.

	// The user profile will be 'email=foo@bar.comma&uid=10&role=user'.
	// If we split it into 16 bytes blocks we have:

	// B0: email=foo@bar.co
	// B1: mma&uid=10&role=
	// B2: user[  padding ]

	// The last block (B2) has to be replaced with a different one, so
	// the crafted user profile will have role=admin.

	// To achieve this, a profile for a different user must be used.
	// We need to use an email address such that a block with only the
	// 'admin' word must exist. Considering that this block will replace
	// the original B2 block, this word must be padded to work.

	// Let's try to use the 'foo@bar.coadmin' as email, but padded, so
	// the final email will be 'foo@bar.co' concatenated with 'admin'
	// concatenated with the needed padding (11 bytes in this case).

	// The new user profile will have the following blocks:

	// C0: email=foo@bar.co
	// C1: admin[ padding ]
	// C2: &uid=10&role=use
	// C3: r[   padding   ]

	// For final step B2 block of the normal user profile will be
	// replaced with the C1 block of the crafted user profile.

	// In the end, the admin user profile will result:

	// B0: email=foo@bar.co
	// B1: mma&uid=10&role=
	// B2: admin[ padding ]

	email := []byte("foo@bar.comma")

	userProfile, err := profileFor(email)
	if err != nil {
		t.Error("Failed to create user profile:", err)
	}

	expectedUserProfile := []byte("email=foo@bar.comma&uid=10&role=user")

	if !bytes.Equal(userProfile, expectedUserProfile) {
		t.Error("Failed to create initial user profile, expected", expectedUserProfile, "got", userProfile)
	}

	key := []byte("Q#K6Th1T6uFa27R)")

	encryptedUserProfile, err := encryptUserProfileECB(userProfile, key)
	if err != nil {
		t.Error("Failed to encrypt user profile:", err)
	}

	admin := []byte("admin")
	craftedEmail := []byte("foo@bar.co")
	craftedEmail = append(craftedEmail, pkcs7padding(admin, aes.BlockSize)...)

	crafedUserProfile, err := profileFor(craftedEmail)
	if err != nil {
		t.Error("Failed to create crafted user profile:", err)
	}

	encryptedCraftedUserProfile, err := encryptUserProfileECB(crafedUserProfile, key)
	if err != nil {
		t.Error("Failed to encrypt crafted user profile:", err)
	}

	copy(encryptedUserProfile[32:], encryptedCraftedUserProfile[16:32])

	decryptedUserProfile, err := decryptUserProfileECB(encryptedUserProfile, key)
	if err != nil {
		t.Error("Failed to decrypt user profile:", err)
	}

	// remove the added padding from the final cipher text
	decryptedUserProfile = decryptedUserProfile[:len(decryptedUserProfile)-(aes.BlockSize-len(admin))]

	expectedDecryptedUserProfile := []byte("email=foo@bar.comma&uid=10&role=admin")

	if !bytes.Equal(decryptedUserProfile, expectedDecryptedUserProfile) {
		t.Error("Failed to create admin user profile, expected", expectedDecryptedUserProfile, "got", decryptedUserProfile)
	}
}
