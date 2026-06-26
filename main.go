// Command bip39wordstokey derives the Ethereum private key and address from a
// BIP39 mnemonic at m/44'/60'/0'/0/0. Input comes from arguments, a file (-f),
// or stdin, one phrase per line.
package main

import (
	"bufio"
	_ "embed"
	"fmt"
	"os"
	"strings"
)

//go:embed english.txt
var englishWordList string

var (
	wordList  []string
	wordIndex map[string]int
)

func init() {
	wordList = strings.Fields(englishWordList)
	wordIndex = make(map[string]int, len(wordList))
	for i, word := range wordList {
		wordIndex[word] = i
	}
}

func convert(line string) (string, error) {
	mnemonic := strings.Join(strings.Fields(strings.ToLower(line)), " ")
	if _, err := Decode(mnemonic); err != nil {
		return "", err
	}
	privateKey, address, err := deriveEthereum(mnemonic, "")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("private key: %s\naddress:     %s", privateKey, address), nil
}

func main() {
	args := os.Args[1:]
	if len(args) >= 2 && args[0] == "-f" {
		file, err := os.Open(args[1])
		if err != nil {
			fail(err)
		}
		defer file.Close()
		runLines(bufio.NewScanner(file))
		return
	}
	if len(args) > 0 {
		printConverted(strings.Join(args, " "))
		return
	}
	runLines(bufio.NewScanner(os.Stdin))
}

func runLines(scanner *bufio.Scanner) {
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		printConverted(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fail(err)
	}
}

func printConverted(line string) {
	out, err := convert(line)
	if err != nil {
		fail(err)
	}
	fmt.Println(out)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
