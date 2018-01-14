package set2

import (
	"bytes"
	"errors"
)

func pkcs7unpadding(paddedText []byte, blockSize int) ([]byte, error) {
	var text []byte

	textLength := len(paddedText)
	if textLength%blockSize != 0 {
		return nil, errors.New("Padded text not multiple of blocksize")
	}

	lastByte := paddedText[textLength-1]
	if lastByte > 0 && lastByte < 16 {
		textPadding := paddedText[textLength-int(lastByte):]
		validPadding := bytes.Repeat([]byte{lastByte}, int(lastByte))

		if bytes.Equal(textPadding, validPadding) {
			text = paddedText[:textLength-int(lastByte)]
		}
	}

	return text, nil
}
