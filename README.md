# bip39wordstokey

Turns a BIP39 mnemonic into its Ethereum wallet key. Given a phrase it derives the seed (PBKDF2-HMAC-SHA512), the BIP32 master key, and the account at `m/44'/60'/0'/0/0`, then prints the secp256k1 private key and the EIP-55 checksummed address. The mnemonic checksum is verified first, so a mistyped phrase is rejected instead of silently deriving a wrong key.

## Build

```
go build -o bip39wordstokey .
```

## Use

Pass the phrase as arguments:

```
./bip39wordstokey abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
# private key: 0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727
# address:     0x9858EfFD232B4033E47d90003D41EC34EcaEda94
```

From a file or stdin, one phrase per line:

```
./bip39wordstokey -f phrases.txt
cat phrases.txt | ./bip39wordstokey
```

## Notes

- Supports the standard BIP39 sizes: 12, 15, 18, 21 and 24 words.
- The English word list (`english.txt`) is the official BIP39 list, embedded into the binary.
- Derivation is fixed to the Ethereum account-0 path `m/44'/60'/0'/0/0` with an empty passphrase, matching MetaMask and the iancoleman BIP39 tool.
- It never touches the network, but it prints real private keys. Run it offline and keep the phrase and output secret.

## Test

```
go test ./...
```

Tested against the canonical `m/44'/60'/0'/0/0` vector.
