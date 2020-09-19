package libkarai

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
)

const appName = "libkarai-go"
const appDev = "RockSteadyTC"
const appDescription = appName + " a Go library for interacting with Karai"
const appLicense = "https://choosealicense.com/licenses/mit/"
const appRepository = "https://github.com/karai/libkarai-go"
const appURL = "https://karai.io"

var (
	isNew bool
	// isTrusted bool
)

// ED25519Keys This is a struct for holding keys and a signature.
type ED25519Keys struct {
	publicKey  string
	privateKey string
	signedKey  string
	selfCert   string
}

// Version Prints the semver of libkarai-go as string
func Version() string {
	var major, minor, patch, version string
	major = "0"
	minor = "1"
	patch = "2"
	version = major + "." + minor + "." + patch
	return version
}

// Send Takes a data string and a websocket connection
func Send(msg string, conn *websocket.Conn) error {
	err := conn.WriteMessage(1, []byte("send "+msg))
	handle("There was a problem sending your transaction ", err)
	return err
}

// JoinChannel Takes a ktx address with port, boolean for new or returning, and keys. Outputs a websocket and CA cert
func JoinChannel(ktx string, isNew bool, keyCollection *ED25519Keys) (*websocket.Conn, string) {
	// request a websocket connection
	var conn = requestSocket(ktx, "1")
	// using that connection, attempt to join the channel
	var joinedChannel = joinStatement(conn, isNew, keyCollection)
	// parse channel messages
	cert := socketMsgParser(ktx, joinedChannel, keyCollection)
	// return the connection
	return conn, cert
}

func joinStatement(conn *websocket.Conn, isNew bool, keyCollection *ED25519Keys) *websocket.Conn {
	// new users should send JOIN with the pubkey
	if isNew {
		joinReq := "JOIN " + keyCollection.publicKey[:64]
		_ = conn.WriteMessage(1, []byte(joinReq))
	}
	// returning users should send RTRN and the signed CA cert
	if !isNew {
		rtrnReq := "RTRN " + keyCollection.publicKey[:64] + " " + keyCollection.selfCert
		_ = conn.WriteMessage(1, []byte(rtrnReq))
	}
	return conn
}

func returnMessage(conn *websocket.Conn, pubKey string, keyCollection *ED25519Keys) *websocket.Conn {
	if !isNew {
		rtrnReq := "RTRN " + pubKey[:64] + " " + keyCollection.selfCert
		_ = conn.WriteMessage(1, []byte(rtrnReq))
	}
	return conn
}

func requestSocket(ktx, protocolVersion string) *websocket.Conn {
	urlConnection := url.URL{Scheme: "ws", Host: ktx, Path: "/api/v" + protocolVersion + "/channel"}
	conn, _, err := websocket.DefaultDialer.Dial(urlConnection.String(), nil)
	handle("There was a problem connecting to the channel: ", err)
	return conn
}

// SignKey Takes a key set and an ed25519 public key string parameter to sign a key. Returns a signature of the key signed with the key set.
func SignKey(keyCollection *ED25519Keys, publicKey string) string {
	messageBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		panic(err)
	}
	privateKey, err := hex.DecodeString(keyCollection.privateKey)
	if err != nil {
		panic(err)
	}
	pubKey, err := hex.DecodeString(keyCollection.publicKey)
	if err != nil {
		panic(err)
	}
	privateKey = append(privateKey, pubKey...)
	signature := ed25519.Sign(privateKey, messageBytes)
	return hex.EncodeToString(signature)
}

func socketMsgParser(ktx string, conn *websocket.Conn, keyCollection *ED25519Keys) string {
	_, joinResponse, err := conn.ReadMessage()
	handle("There was a problem reading the socket: ", err)
	if strings.HasPrefix(string(joinResponse), "WCBK") {
		isNew = false
		return string(joinResponse)
	}
	if strings.Contains(string(joinResponse), "CAPK") {
		convertjoinResponseString := string(joinResponse)
		trimNewLinejoinResponse := strings.TrimRight(convertjoinResponseString, "\n")
		trimCmdPrefix := strings.TrimPrefix(trimNewLinejoinResponse, "CAPK ")
		ncasMsgtring := SignKey(keyCollection, trimCmdPrefix[:64])
		composedNcasMsgtring := "NCAS " + ncasMsgtring
		_ = conn.WriteMessage(1, []byte(composedNcasMsgtring))
		_, certResponse, _ := conn.ReadMessage()
		isNew = false
		return string(certResponse)
	}
	return "The stars did not align, you were denied access."
}

// GenerateKeys Generates ed25519 keyset as strings
func GenerateKeys() *ED25519Keys {
	keys := ED25519Keys{}
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		handle("error: ", err)
	}
	keys.privateKey = hex.EncodeToString(privKey[0:32])
	keys.publicKey = hex.EncodeToString(pubKey)
	signedKey := ed25519.Sign(privKey, pubKey)
	keys.signedKey = hex.EncodeToString(signedKey)
	keys.selfCert = keys.publicKey + keys.signedKey
	return &keys
}

// handle Ye Olde Error Handler takes a message and an error code
func handle(msg string, err error) {
	if err != nil {
		fmt.Printf("\n%s: %s", msg, err)
	}
}

// Sign Takes keys and a message to sign
func Sign(keyCollection *ED25519Keys, msg string) string {
	messageBytes := []byte(msg)
	privateKey, err := hex.DecodeString(keyCollection.privateKey)
	if err != nil {
		panic(err)
	}
	publicKey, err := hex.DecodeString(keyCollection.publicKey)
	if err != nil {
		panic(err)
	}
	privateKey = append(privateKey, publicKey...)
	signature := ed25519.Sign(privateKey, messageBytes)
	return hex.EncodeToString(signature)
}

// VerifySignature Takes a public key, a message, and a signature. This will return true if it verifies correctly.
func VerifySignature(publicKey string, msg, signature string) bool {
	pubKey, err := hex.DecodeString(publicKey)
	if err != nil {
		panic(err)
	}
	messageBytes := []byte(msg)
	sig, err := hex.DecodeString(signature)
	if err != nil {
		panic(err)
	}
	return ed25519.Verify(pubKey, messageBytes, sig)
}

// VerifySignedKey Takes a public key, a public signing key, and a signature. This will return true if it verifies correctly.
func VerifySignedKey(publicKey string, publicSigningKey string, signature string) bool {
	pubKey, err := hex.DecodeString(publicKey)
	if err != nil {
		panic(err)
	}
	pubSignKey, err := hex.DecodeString(publicSigningKey)
	if err != nil {
		panic(err)
	}
	sig, err := hex.DecodeString(signature)
	if err != nil {
		panic(err)
	}
	return ed25519.Verify(pubSignKey, pubKey, sig)
}
