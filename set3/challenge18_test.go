package set3

import (
    "bytes"
    "encoding/base64"
    "testing"
)

func TestDecryptAesCTRMode(t *testing.T)  {
    cipherText, err := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    if err != nil {
        t.Error("Failed to base64 decode")
    }

    plainText, err := decryptAesCTRMode(cipherText, []byte("YELLOW SUBMARINE"), []byte{0,0,0,0,0,0,0,0})
    if err != nil {
        t.Error("Failed to decrypt AES CTR mode:", err)
    }

    expected, err := base64.StdEncoding.DecodeString("WW8sIFZJUCBMZXQncyBraWNrIGl0IEljZSwgSWNlLCBiYWJ5IEljZSwgSWNlLCBiYWJ5IA==")
    if err != nil {
        t.Error("Failed to base64 decode expected string:", err)
    }

    if !bytes.Equal(expected, plainText) {
        t.Error("Failed to decrypt AES CTR cipher text correctly, expected", expected, "got", plainText)
    }
}
