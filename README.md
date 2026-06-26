# bip39wordstokey

A tiny tool that turns a BIP39 mnemonic into its Ethereum wallet key. Given a phrase it derives the BIP39 seed (PBKDF2-HMAC-SHA512), the BIP32 master key, and the account at the standard path `m/44'/60'/0'/0/0`, then prints the entropy, the secp256k1 private key, and the EIP-55 checksummed address:

```
words -> key:   abandon abandon ... about
                entropy:     00000000000000000000000000000000
                private key: 0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727
                address:     0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```

The reverse direction still does the plain entropy ↔ words mapping: a bare hex string is read as entropy and expanded back into words. The checksum is verified when reading a phrase, so a mistyped one is rejected instead of silently returning garbage.

```
key -> words:   00000000000000000000000000000000  ->  abandon abandon ... about
```

## Build

```
go build -o bip39wordstokey .
```

## Use

Words to key (pass the phrase as arguments):

```
./bip39wordstokey abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
# entropy:     00000000000000000000000000000000
# private key: 0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727
# address:     0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```

Key to words (hex, with or without a `0x` prefix):

```
./bip39wordstokey 0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
# legal winner thank year wave sausage worth useful legal winner thank yellow
```

From a file, one phrase or key per line (handy for converting a whole list):

```
./bip39wordstokey -f keys.txt
```

From stdin:

```
echo "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f" | ./bip39wordstokey
```

## What it does and doesn't do

- Supports the standard BIP39 sizes: 12, 15, 18, 21 and 24 words (128 to 256 bits of entropy).
- The English word list (`english.txt`) is the official BIP39 list and is embedded into the binary.
- Derivation is fixed to the Ethereum account-0 path `m/44'/60'/0'/0/0` with an empty passphrase, matching MetaMask and the iancoleman BIP39 tool.
- It never touches the network, but it does print real private keys. Run it offline and keep your phrases and the output secret.

## Test

```
go test ./...
```

Tested against the canonical BIP39 vectors.
