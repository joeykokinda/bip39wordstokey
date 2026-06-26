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

const hardenedOffset uint32 = 0x80000000

// ethereumPath is the standard BIP44 account-0 path: m/44'/60'/0'/0/0.
var ethereumPath = []uint32{
	44 + hardenedOffset,
	60 + hardenedOffset,
	0 + hardenedOffset,
	0,
	0,
}

type extendedKey struct {
	privateKey []byte // 32 bytes
	chainCode  []byte // 32 bytes
}

func mnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	return pbkdf2.Key(sha512.New, mnemonic, []byte("mnemonic"+passphrase), 2048, 64)
}

func newMasterKey(seed []byte) extendedKey {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	sum := mac.Sum(nil)
	return extendedKey{privateKey: sum[:32], chainCode: sum[32:]}
}

func (k extendedKey) child(index uint32) (extendedKey, error) {
	data := make([]byte, 0, 37)
	if index >= hardenedOffset {
		data = append(append(data, 0x00), k.privateKey...)
	} else {
		data = append(data, secp256k1.PrivKeyFromBytes(k.privateKey).PubKey().SerializeCompressed()...)
	}
	data = binary.BigEndian.AppendUint32(data, index)

	mac := hmac.New(sha512.New, k.chainCode)
	mac.Write(data)
	sum := mac.Sum(nil)

	// childKey = (parse256(left) + parentKey) mod n.
	var tweak secp256k1.ModNScalar
	if tweak.SetByteSlice(sum[:32]) {
		return extendedKey{}, fmt.Errorf("derived key %d is invalid (left >= n)", index)
	}
	var parent secp256k1.ModNScalar
	parent.SetByteSlice(k.privateKey)
	tweak.Add(&parent)
	if tweak.IsZero() {
		return extendedKey{}, fmt.Errorf("derived key %d is invalid (zero)", index)
	}
	childKey := tweak.Bytes()
	return extendedKey{privateKey: childKey[:], chainCode: sum[32:]}, nil
}

func derivePath(seed []byte, path []uint32) (extendedKey, error) {
	key := newMasterKey(seed)
	for _, index := range path {
		var err error
		if key, err = key.child(index); err != nil {
			return extendedKey{}, err
		}
	}
	return key, nil
}

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

func publicKeyToAddress(pub *secp256k1.PublicKey) string {
	uncompressed := pub.SerializeUncompressed() // 0x04 || X || Y
	return toChecksumAddress(keccak256(uncompressed[1:])[12:])
}

// toChecksumAddress applies the EIP-55 mixed-case checksum to a 20-byte address.
func toChecksumAddress(addr []byte) string {
	lower := hex.EncodeToString(addr)
	hash := keccak256([]byte(lower))
	out := []byte("0x" + lower)
	for i := range len(lower) {
		c := lower[i]
		if c < 'a' || c > 'f' {
			continue
		}
		nibble := hash[i/2] >> 4
		if i%2 == 1 {
			nibble = hash[i/2] & 0x0f
		}
		if nibble >= 8 {
			out[2+i] = c - 32
		}
	}
	return string(out)
}

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}
