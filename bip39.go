package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

// Decode recovers the entropy from a BIP39 mnemonic and verifies its checksum.
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
	entropyLen := (totalBits - checksumBits) / 8

	checksumMask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(checksumBits)), big.NewInt(1))
	gotChecksum := new(big.Int).And(bits, checksumMask)
	entropyInt := new(big.Int).Rsh(bits, uint(checksumBits))

	entropy := make([]byte, entropyLen)
	entropyInt.FillBytes(entropy)

	sum := sha256.Sum256(entropy)
	want := new(big.Int)
	for i := range checksumBits {
		want.Lsh(want, 1)
		if sum[i/8]&(1<<uint(7-i%8)) != 0 {
			want.SetBit(want, 0, 1)
		}
	}
	if want.Cmp(gotChecksum) != 0 {
		return nil, fmt.Errorf("invalid checksum, the mnemonic is mistyped or not a real BIP39 phrase")
	}

	return entropy, nil
}
