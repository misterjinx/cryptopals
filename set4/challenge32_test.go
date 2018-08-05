package set4

import (
	"bytes"
	"cryptopals/utils"
	"fmt"
	"testing"
	"time"
)

func TestTimingLeakAttackHarder(t *testing.T) {
	file, err := utils.GenerateRandomBytes(32)
	if err != nil {
		t.Error("Failed to generate file name")
	}

	serverUrl := mockWebServerUrl(5 * time.Microsecond) // using a value that does not take too much time waiting
	numberOfBytesToRecover := 10                        // recover only first 10 bytes in order to reduce the total time it takes the test to finish (aka brute force time)
	signature := recoverSignatureUsingTimingAttackHarder(file, serverUrl, numberOfBytesToRecover)

	t.Log("Recovered signature is", fmt.Sprintf("%x", signature))

	expectedSignature := getFileSignature(file)

	t.Log("Expected signature was", fmt.Sprintf("%x", expectedSignature))

	if !bytes.Equal(signature[:numberOfBytesToRecover], expectedSignature[:numberOfBytesToRecover]) {
		t.Error("Failed to recover HMAC using timing leak attack harder")
	}
}
