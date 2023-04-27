package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/arielril/aes/pkg/types"
	"github.com/projectdiscovery/gologger"
)

func Encrypt(options *types.Options) {
	var encryptedMsg string

	if options.ModeCBC {
		encryptedMsg = encryptCBC(options.Message, options.Key)
	} else if options.ModeCTR {
		encryptedMsg = encryptCTR(options.Message, options.Key)
	}

	gologger.Silent().Msgf("encrypted text: \n\n----------------------------\n%s\n----------------------------", encryptedMsg)
}

func encryptCBC(hexMsg, hexKey string) string {
	key, msg, err := decodeHexKeyMsg(hexKey, hexMsg)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		gologger.Fatal().Msgf("could not create aes cipher: %s\n", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(msg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		gologger.Fatal().Msgf("could not create iv: %s\n", err)
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(cipherText[aes.BlockSize:], pkcs5Padding(cipherText, aes.BlockSize))

	return string(cipherText)
}

func encryptCTR(hexMsg, hexKey string) string {
	key, msg, err := decodeHexKeyMsg(hexKey, hexMsg)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	return string(key) + string(msg)
}
