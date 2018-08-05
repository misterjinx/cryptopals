package set4

import "time"

/**
 * Based on the pseudocode from https://en.wikipedia.org/wiki/HMAC
 */
func hmacSha1(key []byte, message []byte) []byte {
	// blockSize for SHA1 is 64 bytes
	blockSize := 64

	// Keys longer than blockSize are shortened by hashing them
	if len(key) > blockSize {
		sha1Key := NewSHA1()
		key = sha1Key.Sum(key) // Key becomes outputSize bytes long
	}

	// Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
	if len(key) < blockSize {
		// pad key with zeros to make it blockSize bytes long
		for i := len(key); i < blockSize; i++ {
			key = append(key, byte(0x00))
		}
	}

	o_key_pad := make([]byte, blockSize) // Outer padded key
	i_key_pad := make([]byte, blockSize) // Inner padded key

	copy(o_key_pad, key)
	copy(i_key_pad, key)

	for i := range o_key_pad {
		o_key_pad[i] ^= 0x5c
	}

	for i := range i_key_pad {
		i_key_pad[i] ^= 0x36
	}

	// HMAC is hash(o_key_pad ∥ hash(i_key_pad ∥ message)) // Where ∥ is concatenation

	sha1Inner := NewSHA1()
	innerHash := sha1Inner.Sum(append(i_key_pad, message...))

	sha1Outer := NewSHA1()
	hmac := sha1Outer.Sum(append(o_key_pad, innerHash...))

	return hmac
}

/**
 * Compare if two messages are equal using early exit
 */
func insecureCompare(a []byte, b []byte, wait time.Duration) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
		time.Sleep(wait)
	}

	return true
}

/**
 * Returns an HMAC computed with a "secret" key
 */
func getFileSignature(file []byte) []byte {
	// to make it easier, I'll use the md4 of the file name as the key
	// in order to have the same key every time when doing checks
	md4 := NewMD4()
	key := md4.Sum(file)

	return hmacSha1(key, file)
}

/**
 * To make it faster to test the timing leak attack, instead of using a
 * separated web server, I'm gonna use this function.
 *
 * This "server" receives a duration to pass to the comparison function,
 * and returns a function that acts like an oracle, it returns true
 * if signature is valid, false otherwise.
 */
func mockWebServerUrl(wait time.Duration) func(file []byte, signature []byte) bool {
	return func(file []byte, signature []byte) bool {
		hmac := getFileSignature(file)

		return insecureCompare(hmac, signature, wait)
	}
}

/**
 * By passing a number of bytes to recover it will speed up the process
 * and only check for the first number of specified bytes.
 */
func recoverSignatureUsingTimingAttack(file []byte, serverUrl func(file []byte, signature []byte) bool, numberOfBytesToRecover int) []byte {
	signature := make([]byte, SHA1DigestSize) // this will be the recovered hmac

	if numberOfBytesToRecover > len(signature) {
		numberOfBytesToRecover = len(signature)
	}

	for i := 0; i < numberOfBytesToRecover; i++ {
		longestTime := time.Microsecond // start with something way to low
		currentByte := 0

		for c := 0; c <= 255; c++ {
			signature[i] = byte(c)

			start := time.Now()
			serverUrl(file, signature)
			elapsed := time.Since(start)

			if elapsed > longestTime {
				longestTime = elapsed
				currentByte = c
			}
		}

		signature[i] = byte(currentByte)
	}

	return signature
}
