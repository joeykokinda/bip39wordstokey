# bip39wordstokey

A tiny tool that converts between BIP39 mnemonic words and their underlying key, in both directions. The "key" is the BIP39 entropy that the words encode (shown in hex), so the mapping is fully reversible:

```
words -> key:   abandon abandon ... about           ->  00000000000000000000000000000000
key   -> words: 00000000000000000000000000000000     ->  abandon abandon ... about
```

It auto-detects which way to go from the input: a bare hex string becomes words, anything else is read as a phrase and turned back into its key. The checksum is verified on the way back, so a mistyped phrase is rejected instead of silently returning garbage.

## Build

```
go build -o bip39wordstokey .
```

## Use

Words to key (pass the phrase as arguments):

```
./bip39wordstokey abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
# 00000000000000000000000000000000
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
- This is the pure words ↔ entropy mapping. It is not a wallet: it does not derive seeds, addresses, or per-coin private keys, and it never touches the network. Keep your real phrases offline.

## Test

```
go test ./...
```

Tested against the canonical BIP39 vectors.
