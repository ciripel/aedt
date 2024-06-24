package core

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/ciripel/aedt/bip39"
)

func Encrypt(flag string) {
	flags := strings.Split(flag, ":")
	if len(flags) < 2 {
		slog.Error("you forgot to enter a password. Passwords must be min 8 characters")
		return
	}
	mnemonicStr := flags[0]
	if !bip39.IsMnemonicValid(mnemonicStr) {
		slog.Error("mnemonic is invalid")
		return
	}

	mnemonic := strings.Fields(mnemonicStr)

	password := flags[1]
	if len(password) < 8 {
		slog.Error("password must have minimum 8 characters")
		return
	}

	passAsciiValues := make([]int, len(password))
	for i, char := range password {
		passAsciiValues[i] = int(char)
	}

	wk, wv := bip39.GetWords()

	mnemonicIntValues := make([]int, len(mnemonic))
	for i, word := range mnemonic {
		mnemonicIntValues[i] = wk[word]
	}

	passwordAsciiExtended := make([]int, len(mnemonicIntValues))

	for i := range passwordAsciiExtended {
		passwordAsciiExtended[i] = passAsciiValues[i%len(passAsciiValues)]
	}

	newMnemonicIntValues := make([]int, len(mnemonicIntValues))

	for i := 0; i < len(mnemonicIntValues); i++ {
		sum := mnemonicIntValues[i] + passwordAsciiExtended[i]
		if sum > 2048 {
			sum -= 2048
		}
		newMnemonicIntValues[i] = sum
	}

	newMnemonic := make([]string, len(newMnemonicIntValues))

	for i, wordIndex := range newMnemonicIntValues {
		newMnemonic[i] = wv[wordIndex]
	}

	fmt.Printf("Encrypted\nmnemonic=%s\nwith password=%s\nRESULT=%s\n", mnemonicStr, password, strings.Join(newMnemonic, " "))
}

func Decrypt(flag string) {
	flags := strings.Split(flag, ":")
	if len(flags) < 2 {
		slog.Error("you forgot to enter a password. Passwords must be min 8 characters")
		return
	}
	mnemonicStr := flags[0]

	mnemonic := strings.Fields(mnemonicStr)

	password := flags[1]
	if len(password) < 8 {
		slog.Error("password must have minimum 8 characters")
		return
	}

	passAsciiValues := make([]int, len(password))
	for i, char := range password {
		passAsciiValues[i] = int(char)
	}

	wk, wv := bip39.GetWords()

	mnemonicIntValues := make([]int, len(mnemonic))
	for i, word := range mnemonic {
		mnemonicIntValues[i] = wk[word]
	}

	passwordAsciiExtended := make([]int, len(mnemonicIntValues))

	for i := range passwordAsciiExtended {
		passwordAsciiExtended[i] = passAsciiValues[i%len(passAsciiValues)]
	}

	newMnemonicIntValues := make([]int, len(mnemonicIntValues))

	for i := 0; i < len(mnemonicIntValues); i++ {
		dif := mnemonicIntValues[i] - passwordAsciiExtended[i]
		if dif < 1 {
			dif += 2048
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

	fmt.Printf("Decrypted\nmnemonic=%s\nwith password=%s\nRESULT=%s\n", mnemonicStr, password, newMnemonicStr)
}
