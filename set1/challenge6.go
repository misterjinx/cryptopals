package set1

import (
	"errors"
	"fmt"
)

func hammingDistance(s1 string, s2 string) (int, error) {
	if len(s1) != len(s2) {
		return -1, errors.New("Undefined for strings of unequal length")
	}

	distance := 0

	for i := range s1 {
		if s1[i] != s2[i] {
			distance += 1
		}
	}

	return distance, nil
}

func stringToBinary(s string) string {
	result := ""
	for _, c := range s {
		result = fmt.Sprintf("%s%.8b", result, c)
	}
	return result
}
