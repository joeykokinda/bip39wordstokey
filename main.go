// Command bip39wordstokey turns a BIP39 mnemonic into its Ethereum wallet key.
// Given a phrase it derives the seed (BIP39 PBKDF2), the BIP32 master key, and
// the account at the standard path m/44'/60'/0'/0/0, then prints the entropy,
// the secp256k1 private key, and the EIP-55 checksummed address.
//
// The reverse direction still works for the plain entropy <-> words mapping: a
// bare hex string is treated as entropy and expanded back into words.
//
//	words -> key:   abandon abandon ... about  ->  entropy / private key / address
//	key   -> words: 00000000000000000000000000000000  ->  abandon abandon ... about
//
// Input can come from arguments, a file (-f), or stdin. Each non-empty line
// is converted independently, so a file with many phrases or keys just works.
package main

import (
	"bufio"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
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

var hexOnly = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// convert decides the direction from the input and returns the converted line.
func convert(line string) (string, error) {
	trimmed := strings.TrimSpace(line)
	compact := strings.ReplaceAll(strings.TrimPrefix(strings.ToLower(trimmed), "0x"), " ", "")

	// A bare hex string is a key, so turn it into words.
	if hexOnly.MatchString(compact) && len(strings.Fields(trimmed)) == 1 {
		entropy, err := hex.DecodeString(compact)
		if err != nil {
			return "", err
		}
		return Encode(entropy)
	}

	// Otherwise treat it as a mnemonic. Decode validates the checksum and
	// recovers the entropy; derivation gives the Ethereum key and address.
	entropy, err := Decode(trimmed)
	if err != nil {
		return "", err
	}
	mnemonic := normalizeMnemonic(trimmed)
	privateKey, address, err := deriveEthereum(mnemonic, "")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("entropy:     %s\nprivate key: %s\naddress:     %s",
		hex.EncodeToString(entropy), privateKey, address), nil
}

// normalizeMnemonic lowercases the phrase and collapses runs of whitespace to a
// single space so the PBKDF2 input matches the canonical BIP39 form.
func normalizeMnemonic(mnemonic string) string {
	return strings.Join(strings.Fields(strings.ToLower(mnemonic)), " ")
}

func main() {
	var fileName string
	args := os.Args[1:]
	if len(args) >= 2 && args[0] == "-f" {
		fileName = args[1]
		args = args[2:]
	}

	switch {
	case fileName != "":
		file, err := os.Open(fileName)
		if err != nil {
			fail(err)
		}
		defer file.Close()
		runLines(bufio.NewScanner(file))
	case len(args) > 0:
		// All remaining args are treated as one input (a phrase or a key).
		printConverted(strings.Join(args, " "))
	default:
		runLines(bufio.NewScanner(os.Stdin))
	}
}

func runLines(scanner *bufio.Scanner) {
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		printConverted(line)
	}
	if err := scanner.Err(); err != nil {
		fail(err)
	}
}

func printConverted(line string) {
	out, err := convert(line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
