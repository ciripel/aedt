package constants

import "errors"

var (
	// ErrInvalidMnemonic is returned when trying to use a malformed mnemonic.
	ErrInvalidMnemonic = errors.New("invalid mnemonic")

	// ErrChecksumIncorrect is returned when entropy has the incorrect checksum.
	ErrChecksumIncorrect = errors.New("checksum incorrect")

	// ErrMissingPassword is returned when user forgot to enter a password.
	ErrMissingPassword = errors.New("you forgot to enter a password. Passwords must be min 8 characters")

	// ErrInvalidPassword is returned when password has less than 8 characters
	ErrInvalidPassword = errors.New("password must have minimum 8 characters")
)
