package set1

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"reflect"
	"testing"
)

func TestHammingDistance(t *testing.T) {
	s1 := "this is a test"
	s2 := "wokka wokka!!!"

	expected := 37

	// pass the strings as their binary representation
	distance, err := hammingDistance([]byte(s1), []byte(s2))
	if err != nil {
		t.Error("Hamming distance error", err)
	}

	if distance != expected {
		t.Error("Failed to calculate hamming distance, expected", expected, "got", distance)
	}
}

func TestArrayChunk(t *testing.T) {
	input := []byte("abcdefghij")
	expected := [][]byte{{97, 98, 99}, {100, 101, 102}, {103, 104, 105}, {106}}

	actual := ChunkArray(input, 3)

	if !reflect.DeepEqual(actual, expected) {
		t.Error("Failed to chunk array. Expected", expected, "got", actual)
	}
}

func TestBreakVigenere(t *testing.T) {
	content, err := ioutil.ReadFile("./6.txt")
	if err != nil {
		t.Fatal(err)
	}

	decodedContent, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		t.Fatal(err)
	}

	expectedKey, err := base64.StdEncoding.DecodeString("VGVybWluYXRvciBYOiBCcmluZyB0aGUgbm9pc2U=")
	if err != nil {
		t.Fatal("Failed to base64 decode expected key: ", err)
	}

	expectedOutputEncoded, err := ioutil.ReadFile("./6.out")
	if err != nil {
		t.Fatal("Failed to read base64 encoded expected output: ", err)
	}

	expectedOutput, err := base64.StdEncoding.DecodeString(string(expectedOutputEncoded))
	if err != nil {
		t.Fatal("Failed to base64 decode expected output: ", err)
	}

	actualOutput, actualKey := breakVigenere(decodedContent)

	if !bytes.Equal(actualKey, expectedKey) {
		t.Error("Failed to find the correct key to decrypt Vigenere cipher")
	}

	if !bytes.Equal(actualOutput, expectedOutput) {
		t.Error("Failed to decrypt Vigenere cipher")
	}
}
