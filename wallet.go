package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// hardenedOffset marks BIP32 hardened derivation indexes.
const hardenedOffset uint32 = 0x80000000

// ethereumPath is the standard BIP44 account-0 path used by MetaMask and most
// EVM wallets: m/44'/60'/0'/0/0.
var ethereumPath = []uint32{
	44 + hardenedOffset,
	60 + hardenedOffset,
	0 + hardenedOffset,
	0,
	0,
}

// extendedKey is a BIP32 private key together with its chain code.
type extendedKey struct {
	privateKey []byte // 32 bytes
	chainCode  []byte // 32 bytes
}

// mnemonicToSeed runs the BIP39 PBKDF2-HMAC-SHA512 stretch (2048 rounds) over
// the mnemonic to produce the 64-byte seed.
func mnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	return pbkdf2.Key(sha512.New, mnemonic, []byte("mnemonic"+passphrase), 2048, 64)
}

// newMasterKey derives the BIP32 master key from a seed.
func newMasterKey(seed []byte) extendedKey {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	sum := mac.Sum(nil)
	return extendedKey{privateKey: sum[:32], chainCode: sum[32:]}
}

// child derives the BIP32 child key at the given index.
func (k extendedKey) child(index uint32) (extendedKey, error) {
	data := make([]byte, 0, 37)
	if index >= hardenedOffset {
		// Hardened: 0x00 || parent private key.
		data = append(data, 0x00)
		data = append(data, k.privateKey...)
	} else {
		// Normal: compressed parent public key.
		parent := secp256k1.PrivKeyFromBytes(k.privateKey)
		data = append(data, parent.PubKey().SerializeCompressed()...)
	}
	data = binary.BigEndian.AppendUint32(data, index)

	mac := hmac.New(sha512.New, k.chainCode)
	mac.Write(data)
	sum := mac.Sum(nil)
	left, chainCode := sum[:32], sum[32:]

	// childKey = (parse256(left) + parentKey) mod n.
	var tweak secp256k1.ModNScalar
	if tweak.SetByteSlice(left) {
		return extendedKey{}, fmt.Errorf("derived key %d is invalid (left >= n)", index)
	}
	var parent secp256k1.ModNScalar
	parent.SetByteSlice(k.privateKey)
	tweak.Add(&parent)
	if tweak.IsZero() {
		return extendedKey{}, fmt.Errorf("derived key %d is invalid (zero)", index)
	}
	childKey := tweak.Bytes()

	return extendedKey{privateKey: childKey[:], chainCode: chainCode}, nil
}

// derivePath walks a full BIP32 derivation path from a seed.
func derivePath(seed []byte, path []uint32) (extendedKey, error) {
	key := newMasterKey(seed)
	for _, index := range path {
		var err error
		key, err = key.child(index)
		if err != nil {
			return extendedKey{}, err
		}
	}
	return key, nil
}

// deriveEthereum turns a BIP39 mnemonic into the Ethereum private key and
// checksummed address at m/44'/60'/0'/0/0.
func deriveEthereum(mnemonic, passphrase string) (privateKey, address string, err error) {
	seed, err := mnemonicToSeed(mnemonic, passphrase)
	if err != nil {
		return "", "", err
	}
	key, err := derivePath(seed, ethereumPath)
	if err != nil {
		return "", "", err
	}
	priv := secp256k1.PrivKeyFromBytes(key.privateKey)
	return "0x" + hex.EncodeToString(key.privateKey), publicKeyToAddress(priv.PubKey()), nil
}

// publicKeyToAddress derives the EIP-55 checksummed address from a public key:
// the last 20 bytes of keccak256(X || Y).
func publicKeyToAddress(pub *secp256k1.PublicKey) string {
	uncompressed := pub.SerializeUncompressed() // 0x04 || X || Y
	hash := keccak256(uncompressed[1:])
	return toChecksumAddress(hash[12:])
}

// toChecksumAddress applies the EIP-55 mixed-case checksum to a 20-byte address.
func toChecksumAddress(addr []byte) string {
	lower := hex.EncodeToString(addr)
	hash := keccak256([]byte(lower))
	out := []byte("0x" + lower)
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if c < 'a' || c > 'f' {
			continue
		}
		nibble := hash[i/2] >> 4
		if i%2 == 1 {
			nibble = hash[i/2] & 0x0f
		}
		if nibble >= 8 {
			out[2+i] = c - 32 // to uppercase
		}
	}
	return string(out)
}

// keccak256 is the Ethereum-flavoured (pre-standard) Keccak-256.
func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}
