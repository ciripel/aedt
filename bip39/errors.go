package bip39

import "errors"

var (
	// ErrInvalidMnemonic is returned when trying to use a malformed mnemonic.
	errInvalidMnemonic = errors.New("invalid mnemonic")

	// ErrChecksumIncorrect is returned when entropy has the incorrect checksum.
	errChecksumIncorrect = errors.New("checksum incorrect")
)
