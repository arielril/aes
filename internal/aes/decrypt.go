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

func Decrypt(options *types.Options) {
	gologger.Debug().Msg("decrypting message")
	var msg string

	if options.ModeCBC {
		msg = decryptCBC(options.Message, options.Key)
	} else if options.ModeCTR {
		msg = decryptCTR(options.Message, options.Key)
	}

	gologger.Silent().Msgf("decrypted message: %s\n", msg)
}

func decryptCBC(hexEncryptedMsg, hexKey string) string {
	key, encryptedMsg, err := decodeHexKeyMsg(hexKey, hexEncryptedMsg)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		gologger.Fatal().Msgf("could not create aes cipher: %s\n", err)
	}

	// in aes CBC, the message must be at least the size of one block
	if len(encryptedMsg) < aes.BlockSize {
		gologger.Fatal().Msgf("encrypted message is too short")
	}

	iv := encryptedMsg[:aes.BlockSize]
	encryptedMsg = encryptedMsg[aes.BlockSize:]
	if len(encryptedMsg)%aes.BlockSize != 0 {
		gologger.Fatal().Msgf("encrypted message size is not a multiple of the block size")
	}
	gologger.Info().Msgf("using iv=%s\n", hex.EncodeToString(iv))

	mode := cipher.NewCBCDecrypter(aesBlock, []byte(iv))
	decryptedMsg := make([]byte, len(encryptedMsg))
	mode.CryptBlocks(decryptedMsg, []byte(encryptedMsg))

	return hex.EncodeToString(pkcs5Trimming(decryptedMsg))
}

func decryptCTR(hexMsg, hexKey string) string {
	key, msg, err := decodeHexKeyMsg(hexKey, hexMsg)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		gologger.Fatal().Msgf("could not create aes cipher :%s\n", err)
	}

	decryptedMsg := make([]byte, len(msg)+aes.BlockSize)
	iv := msg[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		gologger.Fatal().Msgf("could not read iv value: %s\n", err)
	}
	gologger.Info().Msgf("using iv=%s\n", hex.EncodeToString(iv))

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(decryptedMsg, msg[aes.BlockSize:])

	return string(decryptedMsg)
}
