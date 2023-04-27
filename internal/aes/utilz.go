package aes

import (
	"bytes"
	"encoding/hex"

	"github.com/pkg/errors"
)

// decodeHexKeyMsg Translates the Key and Message from hex to a byte slice
func decodeHexKeyMsg(hexKey, hexMsg string) (key, msg []byte, err error) {
	key, err = hex.DecodeString(hexKey)
	if err != nil {
		err = errors.Wrap(err, "could not decode hex key")
		return
	}

	msg, err = hex.DecodeString(hexMsg)
	if err != nil {
		err = errors.Wrap(err, "could not decode hex message")
		return
	}

	return
}

// pkcs5Padding Pad the msg content using PKCS5 algorithm
//
// Code Source: https://gist.github.com/hothero/7d085573f5cb7cdb5801d7adcf66dcf3
func pkcs5Padding(cipherText []byte, blockSize int) []byte {
	paddingLength := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(paddingLength)}, paddingLength)
	return append(cipherText, padText...)
}

// pkcs5Trimming Removes the PKCS5 padding on the encrypted message
func pkcs5Trimming(encryptedText []byte) []byte {
	// the length of the padding IS in the last block, even if it is 0 length
	paddingLength := encryptedText[len(encryptedText)-1]
	return encryptedText[:len(encryptedText)-int(paddingLength)]
}
