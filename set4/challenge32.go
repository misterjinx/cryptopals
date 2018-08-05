package set4

import "time"

/**
 * When there is basically almost no waiting time when comparing bytes,
 * timing the "server" response multiple times and then computing the
 * average time helps getting the desired result.
 *
 * By passing a number of bytes to recover it will speed up the process
 * and only check for the first number of specified bytes.
 */
func recoverSignatureUsingTimingAttackHarder(file []byte, serverUrl func(file []byte, signature []byte) bool, numberOfBytesToRecover int) []byte {
	signature := make([]byte, SHA1DigestSize) // this will be the recovered hmac we recover (max sha1 digest size)

	if numberOfBytesToRecover > len(signature) {
		numberOfBytesToRecover = len(signature)
	}

	for i := 0; i < numberOfBytesToRecover; i++ {
		longestTime := time.Microsecond // start with something way to low
		currentByte := 0

		for c := 0; c <= 255; c++ {
			signature[i] = byte(c)

			start := time.Now()

			// check 20 times for every tested byte and than get the average time it took to get the response
			tries := 20 // for better accuracy this should be higher proportionally to the number of bytes to recover
			for t := 0; t < tries; t++ {
				serverUrl(file, signature)
			}

			elapsed := time.Since(start) / time.Duration(tries)

			if elapsed > longestTime {
				longestTime = elapsed
				currentByte = c
			}
		}

		signature[i] = byte(currentByte)
	}

	return signature
}
