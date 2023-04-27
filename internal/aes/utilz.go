package aes

import (
	"bytes"
	"encoding/hex"

	"github.com/pkg/errors"
)

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

/*
Source: https://gist.github.com/hothero/7d085573f5cb7cdb5801d7adcf66dcf3
*/

func pkcs5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func pkcs5Trimming(encryptedText []byte) []byte {
	padding := encryptedText[len(encryptedText)-1]
	return encryptedText[:len(encryptedText)-int(padding)]
}
