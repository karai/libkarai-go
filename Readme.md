![libkarai](https://user-images.githubusercontent.com/34389545/86527719-73af5200-be67-11ea-9345-ffea6a066fda.png)

[![Discord](https://img.shields.io/discord/388915017187328002?label=Join%20Discord)](http://chat.turtlecoin.lol) [![GitHub issues](https://img.shields.io/github/issues/karai/go-karai?label=Issues)](https://github.com/karai/go-karai/issues) ![GitHub stars](https://img.shields.io/github/stars/karai/go-karai?label=Github%20Stars) ![Build](https://github.com/karai/go-karai/workflows/Build/badge.svg) ![GitHub](https://img.shields.io/github/license/karai/go-karai) ![GitHub issues by-label](https://img.shields.io/github/issues/karai/go-karai/Todo) [![Go Report Card](https://goreportcard.com/badge/github.com/karai/go-karai)](https://goreportcard.com/report/github.com/karai/go-karai)

**Website:** [📝 karai.io](https://karai.io) **Browse:** [💻 Karai Pointer Explorer](https://karaiexplorer.extrahash.org/) **Read:** [🔗 Official Karai Blog](https://karai.io)

## Usage

> Note: Karai aims to always compile and run on **Linux** targetting the **AMD64** CPU architecture. Other operating systems and architectures may compile and run this software but should do so expecting some inconsistencies.

**Import**

```go
import (
  karai "https://github.com/karai/libkarai-go"
)
```

**Methods**

```go
func karai.ConnectChannel(addressport, pubKey, signedKey string)
```

_ConnectChannel() Initiates the connection process to a Karai Transaction Channel_

-   `addressport` is a string that looks like `12.23.34.45:4200` or `zeus.karai.io:4200`
-   `pubKey` is a string ed25519 pubkey that looks like `68b58665c7abf891c2d9b6aaed466d039cedf6c6a701a287165b0d0787235547`
-   `signedkey` is a string ed25519 signature that looks like `490b411f00924fe850d074cc030ccce78a4140bd70d23b2ef3531221e9ac13928f124be7bf493bb5c309239e00b0c90e450ecb495ff6e72e5b16771457911e01`

1.  sends `JOIN <pubKey>` to `addressport`
2.  receives coord signature
3.  sends `PUBK` socket command to get coord public key
4.  receives coord pubkey
5.  validates coord signature with pubkey
6.  sends client signed key
7.  receives client pubkey and cert

```go
func GenerateKeys() *ED25519Keys
```

_GenerateKeys() Fills the ED25519Keys struct with client keys and key signature: `publicKey`, `privateKey`, `signedKey`._

-   `publicKey` is a string ed25519 public key that looks like `68b58665c7abf891c2d9b6aaed466d039cedf6c6a701a287165b0d0787235547`
-   `privateKey` is a string ed25519 private key that looks like `c6a7d9078723554701b6edf6165b0da28768b58665caaed466d039c7abf891c2`
-   `signedKey` is a string ed25519 pubkey signature that looks like `490b411f00924fe850d074cc030ccce78a4140bd70d23b2ef3531221e9ac13928f124be7bf493bb5c309239e00b0c90e450ecb495ff6e72e5b16771457911e01`

```go
type ED25519Keys struct {
	publicKey  string
	privateKey string
	signedKey  string
}
```

```go
func karai.Sign(myKeys *ED25519Keys, msg string) string
```

_Takes a key set and a message parameter to sign an arbitrary string. Returns a signature of the message signed with the key set._

```go
func karai.SignKey(myKeys *ED25519Keys, publicKey string) string
```

_Takes a key set and an ed25519 public key string parameter to sign a key. Returns a signature of the key signed with the key set._

```go
func karai.VerifySignature(publicKey string, msg string, signature string) bool
```

_Takes a public key, a message, and a signature. This will return true if it verifies correctly._

```go
func karai.VerifySignedKey(publicKey string, publicSigningKey string, signature string) bool
```

_Takes a public key, a public signing key, and a signature. This will return true if it verifies correctly._

### Sending and receiving transactions are not yet implemented in libkarai currently.