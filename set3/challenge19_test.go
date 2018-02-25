package set3

import (
	"bytes"
	"cryptopals/set1"
	"cryptopals/utils"
	"encoding/base64"
	"log"
	"testing"
)

var base64strings = [40]string{
	"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
	"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
	"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
	"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
	"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
	"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
	"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
	"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
	"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
	"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
	"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
	"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
	"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
	"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
	"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
	"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
	"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
	"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
	"U2hlIHJvZGUgdG8gaGFycmllcnM/",
	"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
	"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
	"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
	"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
	"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
	"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
	"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
	"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
	"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
	"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
	"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
	"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
	"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
	"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
	"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
	"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
}

func TestBreakFixedNonceCTR(t *testing.T) {
	var plainTexts [][]byte

	for _, b64string := range base64strings {
		plainText, err := base64.StdEncoding.DecodeString(b64string)
		if err != nil {
			t.Error("Failed to base64 decode string", err)
		}

		plainTexts = append(plainTexts, bytes.ToLower(plainText))
	}

	key, err := utils.GenerateRandomAesKey()
	if err != nil {
		log.Println("Failed to generate random AES key:", err)
	}
	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 0}

	cipherTexts := getCTRCipherTexts(plainTexts, key, nonce)

	// crib dragging technique for the first two ciphertexts
	// I'm doing it manually, so bear with me

	c1 := cipherTexts[0]
	c2 := cipherTexts[1]

	cipher := set1.FixedXOR(c1, c2)

	// https://en.wikipedia.org/wiki/Trigram
	// https://en.wikipedia.org/wiki/Most_common_words_in_English

	cribDrag([]byte(" have "), cipher) // => "oming " in 2dn position, so let's try with "coming"

	cribDrag([]byte("coming "), cipher) // => "i have " in 1st position, great

	// after a lot of other tries I tried with "nde"
	cribDrag([]byte("nde"), cipher) // => "the" in 8th position, so let's try with "the" (without any spaces) to see what is on the other side

	cribDrag([]byte("the"), cipher) // => " vi" in 12th position...don't know what words might start with these letters, let's try other cribs starting with "the"

	cribDrag([]byte("them "), cipher) // => " vivi" in 12th position...ok

	// i have ... met?
	cribDrag([]byte("met "), cipher) // => "with", perhaps now try "coming with"

	cribDrag([]byte("coming with"), cipher) // => "i have met", great. let's try "i have met her"

	cribDrag([]byte("i have met her "), cipher) // => nope, after "coming with" we get gibberish

	// i have met ... them ?
	cribDrag([]byte("i have met them "), cipher) // => "coming with vivi". cool

	cribDrag([]byte("i have met them at"), cipher) // "coming with vivid"

	// so far we have "i have met them at" and "coming with vivid "
	// at this point I don't know what other words could be there
	// so I searched for each of the two text and turns out they are from a poem...

	cribDrag([]byte("coming with vivid faces"), cipher) // returns nothing. ok, let's cut down the text a little bit

	cribDrag([]byte("coming with vivid face"), cipher) // => "i have met them at clo"

	// "i have met them at clo" and "coming with vivid face"

	// Turns out these are the two plain text messages that were
	// encrypted using CTR.

	// The length of each of the decrypted text is shorter than the
	// initial plain text because when the ciphertexts were xored
	// they were trimmed to the minimum length of the two.
}
