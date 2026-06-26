package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

// validEntropyBytes are the BIP39 entropy sizes (128, 160, 192, 224, 256 bits).
var validEntropyBytes = map[int]bool{16: true, 20: true, 24: true, 28: true, 32: true}

// Encode turns BIP39 entropy into its mnemonic sentence.
func Encode(entropy []byte) (string, error) {
	if !validEntropyBytes[len(entropy)] {
		return "", fmt.Errorf("entropy must be 16, 20, 24, 28 or 32 bytes, got %d", len(entropy))
	}

	checksumBits := len(entropy) * 8 / 32
	checksum := sha256.Sum256(entropy)

	// Build a big integer holding entropy bits followed by the checksum bits.
	bits := new(big.Int).SetBytes(entropy)
	for i := 0; i < checksumBits; i++ {
		bits.Lsh(bits, 1)
		if checksum[i/8]&(1<<uint(7-i%8)) != 0 {
			bits.SetBit(bits, 0, 1)
		}
	}

	wordCount := (len(entropy)*8 + checksumBits) / 11
	words := make([]string, wordCount)
	mask := big.NewInt(2047)
	index := new(big.Int)
	for i := wordCount - 1; i >= 0; i-- {
		index.And(bits, mask)
		bits.Rsh(bits, 11)
		words[i] = wordList[index.Int64()]
	}

	return strings.Join(words, " "), nil
}

// Decode turns a BIP39 mnemonic sentence back into its entropy and verifies the checksum.
func Decode(mnemonic string) ([]byte, error) {
	words := strings.Fields(strings.ToLower(strings.TrimSpace(mnemonic)))
	switch len(words) {
	case 12, 15, 18, 21, 24:
	default:
		return nil, fmt.Errorf("mnemonic must be 12, 15, 18, 21 or 24 words, got %d", len(words))
	}

	bits := new(big.Int)
	for _, word := range words {
		index, ok := wordIndex[word]
		if !ok {
			return nil, fmt.Errorf("%q is not in the BIP39 word list", word)
		}
		bits.Lsh(bits, 11)
		bits.Or(bits, big.NewInt(int64(index)))
	}

	totalBits := len(words) * 11
	checksumBits := totalBits / 33
	entropyBits := totalBits - checksumBits
	entropyLen := entropyBits / 8

	// Split off the trailing checksum bits.
	checksumMask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(checksumBits)), big.NewInt(1))
	gotChecksum := new(big.Int).And(bits, checksumMask)
	entropyInt := new(big.Int).Rsh(bits, uint(checksumBits))

	entropy := make([]byte, entropyLen)
	entropyInt.FillBytes(entropy)

	wantSum := sha256.Sum256(entropy)
	want := new(big.Int)
	for i := 0; i < checksumBits; i++ {
		want.Lsh(want, 1)
		if wantSum[i/8]&(1<<uint(7-i%8)) != 0 {
			want.SetBit(want, 0, 1)
		}
	}
	if want.Cmp(gotChecksum) != 0 {
		return nil, fmt.Errorf("invalid checksum, the mnemonic is mistyped or not a real BIP39 phrase")
	}

	return entropy, nil
}
