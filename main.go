package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ciripel/aedt/core"
)

func main() {
	e := flag.String("e", "", "encrypt mnemonic with password")
	d := flag.String("d", "", "decrypt mnemonic using password")
	h := flag.Bool("h", false, "show this help")

	flag.Usage = showHelp

	flag.Parse()

	switch {
	case *e != "":
		core.Encrypt(*e)
	case *d != "":
		core.Decrypt(*d)
	case *h:
		showHelp()
	default:
		showHelp()
	}

}

func showHelp() {

	fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Println("\nExamples:")
	fmt.Printf("%s -e \"mnemonic:password\"\n", os.Args[0])
	fmt.Printf("%s -d \"mnemonic:password\"\n", os.Args[0])

}
