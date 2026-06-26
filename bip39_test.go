package main

import (
	"encoding/hex"
	"testing"
)

// Canonical BIP39 test vectors (Trezor english vectors).
var vectors = []struct {
	entropy  string
	mnemonic string
}{
	{
		"00000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
	},
	{
		"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		"legal winner thank year wave sausage worth useful legal winner thank yellow",
	},
	{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
	},
	{
		"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
		"void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
	},
}

func TestEncodeVectors(t *testing.T) {
	for _, v := range vectors {
		entropy, _ := hex.DecodeString(v.entropy)
		got, err := Encode(entropy)
		if err != nil {
			t.Fatalf("Encode(%s): %v", v.entropy, err)
		}
		if got != v.mnemonic {
			t.Errorf("Encode(%s)\n  got:  %q\n  want: %q", v.entropy, got, v.mnemonic)
		}
	}
}

func TestDecodeVectors(t *testing.T) {
	for _, v := range vectors {
		got, err := Decode(v.mnemonic)
		if err != nil {
			t.Fatalf("Decode(%q): %v", v.mnemonic, err)
		}
		if hex.EncodeToString(got) != v.entropy {
			t.Errorf("Decode(%q) = %s, want %s", v.mnemonic, hex.EncodeToString(got), v.entropy)
		}
	}
}

func TestBadChecksum(t *testing.T) {
	bad := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	if _, err := Decode(bad); err == nil {
		t.Fatal("expected checksum error, got nil")
	}
}

func TestUnknownWord(t *testing.T) {
	if _, err := Decode("notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"); err == nil {
		t.Fatal("expected unknown-word error, got nil")
	}
}
