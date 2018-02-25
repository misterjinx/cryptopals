package set1

import (
	"bufio"
	"log"
	"os"
)

func detectSingleCharXOR() ([]byte, byte, float32) {
	file, err := os.Open("./4.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var bestScore float32
	var bestOutput []byte
	var key byte

	bestScore = 0.00

	for scanner.Scan() {
		decr, k, score := DecryptSingleByteXOR(decodeHex(scanner.Text()), nil)

		if score > bestScore {
			bestScore = score
			bestOutput = decr
			key = k
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return bestOutput, key, bestScore
}
