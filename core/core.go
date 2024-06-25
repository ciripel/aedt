package core

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/ciripel/aedt/bip39"
	"github.com/ciripel/aedt/constants"
)

func Encrypt(flag string) {
	mnemonicIntValues, passwordAsciiExtended, wv, err := processFlag(flag, true)
	if err != nil {
		return
	}

	newMnemonicIntValues := make([]int, len(mnemonicIntValues))

	for i := 0; i < len(mnemonicIntValues); i++ {
		sum := mnemonicIntValues[i] + passwordAsciiExtended[i]
		if sum > constants.NUMBER_OF_WORDS {
			sum -= constants.NUMBER_OF_WORDS
		}
		newMnemonicIntValues[i] = sum
	}

	newMnemonic := make([]string, len(newMnemonicIntValues))

	for i, wordIndex := range newMnemonicIntValues {
		newMnemonic[i] = wv[wordIndex]
	}

	fmt.Printf("Encrypted RESULT=%s%s%s\n", constants.ColorGreen, strings.Join(newMnemonic, " "), constants.ColorReset)
}

func Decrypt(flag string) {
	mnemonicIntValues, passwordAsciiExtended, wv, err := processFlag(flag, false)
	if err != nil {
		return
	}

	newMnemonicIntValues := make([]int, len(mnemonicIntValues))

	for i := 0; i < len(mnemonicIntValues); i++ {
		dif := mnemonicIntValues[i] - passwordAsciiExtended[i]
		if dif < 1 {
			dif += constants.NUMBER_OF_WORDS
		}
		newMnemonicIntValues[i] = dif
	}

	newMnemonic := make([]string, len(newMnemonicIntValues))

	for i, wordIndex := range newMnemonicIntValues {
		newMnemonic[i] = wv[wordIndex]
	}
	newMnemonicStr := strings.Join(newMnemonic, " ")
	if !bip39.IsMnemonicValid(newMnemonicStr) {
		slog.Error("mnemonic is invalid")
		return
	}

	fmt.Printf("Decrypted RESULT=%s%s%s\n", constants.ColorGreen, newMnemonicStr, constants.ColorReset)
}

func processFlag(flag string, encrypt bool) (mnemonicIntValues []int, passwordAsciiExtended []int, wv map[int]string, err error) {
	flags := strings.Split(flag, ":")
	if len(flags) < 2 {
		slog.Error("you forgot to enter a password. Passwords must be min 8 characters")
		err = constants.ErrMissingPassword
		return
	}
	mnemonicStr := flags[0]
	if encrypt && !bip39.IsMnemonicValid(mnemonicStr) {
		slog.Error("mnemonic is invalid")
		err = constants.ErrInvalidMnemonic
		return
	}

	mnemonic := strings.Fields(mnemonicStr)

	password := flags[1]
	if len(password) < constants.MIN_PASS_LENGTH {
		slog.Error("password must have minimum 8 characters")
		err = constants.ErrInvalidPassword
		return
	}

	passAsciiValues := make([]int, len(password))
	for i, char := range password {
		passAsciiValues[i] = int(char)
	}

	wk, wv := bip39.GetWords()

	mnemonicIntValues = make([]int, len(mnemonic))
	for i, word := range mnemonic {
		mnemonicIntValues[i] = wk[word]
	}

	passwordAsciiExtended = make([]int, len(mnemonicIntValues))

	for i := range passwordAsciiExtended {
		passwordAsciiExtended[i] = passAsciiValues[i%len(passAsciiValues)]
	}
	fmt.Printf("Mnemonic=%s\nwith password=%s\n", mnemonicStr, password)

	return
}
