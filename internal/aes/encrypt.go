package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/arielril/aes/pkg/types"
	"github.com/projectdiscovery/gologger"
)

// Encrypt Run AES encryption using CBC or CTR modes
func Encrypt(options *types.Options) {
	var encryptedMsg string

	if options.ModeCBC {
		encryptedMsg = encryptCBC(options.Message, options.Key)
	} else if options.ModeCTR {
		encryptedMsg = encryptCTR(options.Message, options.Key)
	}

	gologger.Silent().Msgf("encrypted text: \n----------------------------\n%s\n----------------------------", encryptedMsg)
}

// encryptCBC Encrypts a message using AES CBC mode with a random
// initialization vector (iv)
func encryptCBC(hexMsg, hexKey string) string {
	key, msg, err := decodeHexKeyMsg(hexKey, hexMsg)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		gologger.Fatal().Msgf("could not create aes cipher: %s\n", err)
	}

	msg = pkcs5Padding(msg, aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		gologger.Fatal().Msgf("could not initialize iv: %s\n", err)
	}
	gologger.Info().Msgf("using iv=%s\n", hex.EncodeToString(iv))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], msg)

	return hex.EncodeToString(ciphertext)
}

// encryptCTR Encrypts a message using AES CTR mode
func encryptCTR(hexMsg, hexKey string) string {
	key, msg, err := decodeHexKeyMsg(hexKey, hexMsg)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		gologger.Fatal().Msgf("could not create aes cipher: %s\n", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		gologger.Fatal().Msgf("could initialize iv: %s\n", err)
	}
	gologger.Info().Msgf("using iv=%s\n", hex.EncodeToString(iv))

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, msg)

	return hex.EncodeToString(ciphertext)
}
