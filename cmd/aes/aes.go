package main

import (
	"github.com/arielril/aes/internal/aes"
	"github.com/arielril/aes/pkg/types"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

var options = &types.Options{}

func main() {
	configureFlags()
	validateOptions()

	gologger.Silent().Msg("AES Encryption/Decryption\n\n")

	if options.Encrypt {
		aes.Encrypt(options)
	}

	if options.Decrypt {
		aes.Decrypt(options)
	}
}

func configureFlags() {
	set := goflags.NewFlagSet()
	set.SetDescription("AES Encryption/Decryption")

	setGroup(set, "aes", "aes options",
		set.BoolVarP(&options.Encrypt, "encrypt", "e", false, "run encryption"),
		set.BoolVarP(&options.Decrypt, "decrypt", "d", false, "run decryption"),
		set.StringVarP(&options.Message, "message", "m", "", "message to encrypt/decrypt"),
		set.StringVarP(&options.Key, "key", "k", "", "encryption/decryption key"),
		set.BoolVar(&options.ModeCBC, "cbc", true, "encrypt/decrypt with CBC Mode"),
		set.BoolVar(&options.ModeCTR, "ctr", false, "encrypt/decrypt with CTR Mode"),
	)

	setGroup(set, "output", "output options",
		set.BoolVarP(&options.Silent, "silent", "s", false, "silent output"),
		set.BoolVarP(&options.Verbose, "verbose", "v", false, "verbose output"),
	)
	_ = set.Parse()
}

func validateOptions() {
	if options.Verbose && options.Silent {
		gologger.Fatal().Msg("verbose and silent output chosen")
	}

	if !options.Encrypt && !options.Decrypt {
		gologger.Fatal().Msg("must choose encrypt or decrypt")
	}

	// has message but key wasn't provided
	if options.Message != "" && options.Key == "" {
		gologger.Fatal().Msg("encryption key wasn't provided")
	}
}

func setGroup(set *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	set.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
