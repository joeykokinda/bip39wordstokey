package main

import "testing"

// Canonical BIP44 Ethereum derivation vectors at m/44'/60'/0'/0/0 with an empty
// passphrase, matching the iancoleman BIP39 tool and MetaMask.
var ethVectors = []struct {
	mnemonic   string
	privateKey string
	address    string
}{
	{
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
		"0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
	},
}

func TestDeriveEthereum(t *testing.T) {
	for _, v := range ethVectors {
		privateKey, address, err := deriveEthereum(v.mnemonic, "")
		if err != nil {
			t.Fatalf("deriveEthereum(%q): %v", v.mnemonic, err)
		}
		if privateKey != v.privateKey {
			t.Errorf("private key\n  got:  %s\n  want: %s", privateKey, v.privateKey)
		}
		if address != v.address {
			t.Errorf("address\n  got:  %s\n  want: %s", address, v.address)
		}
	}
}
