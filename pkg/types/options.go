package types

type Options struct {
	Encrypt bool
	Decrypt bool
	ModeCTR bool
	ModeCBC bool

	Message string
	Key     string

	Verbose bool
	Silent  bool
}
