package libkarai

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// ED25519Keys This is a struct for holding keys and a signature.
type ED25519Keys struct {
	publicKey  string
	privateKey string
	signedKey  string
}

const appName = "libkarai-go"
const appDev = "RockSteadyTC"
const appDescription = appName + " a Go library for interacting with Karai"
const appLicense = "https://choosealicense.com/licenses/mit/"
const appRepository = "https://github.com/karai/libkarai-go"
const appURL = "https://karai.io"

var pubkMsg []byte = []byte("PUBK")

// Version Prints the semver of libkarai-go as string
func Version() string {
	var majorSemver, minorSemver, patchSemver, wholeString string
	majorSemver = "0"
	minorSemver = "0"
	patchSemver = "1"
	wholeString = majorSemver + "." + minorSemver + "." + patchSemver
	return wholeString
}

func timeStamp() string {
	current := time.Now()
	return current.Format("2006-01-02 15:04:05")
}

// ConnectChannel Connects to a karai transaction channel using ktx, pubkey, and signedkey strings
func ConnectChannel(addressport, pubKey, signedKey string) {
	// fmt.Printf("\nConnection request with ktx %s", ktx)
	// connect
	// if isCoordinator {
	// 	logrus.Error("This is for nodes running in client mode only.")
	// }
	// if !isCoordinator {
	// Construct a URL for the websocket.
	// For now all that exists is the v1 API, at the /channel
	// endpoint.
	urlConnection := url.URL{Scheme: "ws", Host: addressport, Path: "/api/v1/channel"}
	// Announce the URL we are connecting to
	// fmt.Printf("\nConnecting to %s", urlConnection.String())
	// Make the call to the socket using
	// the URL we composed.
	conn, _, _ := websocket.DefaultDialer.Dial(urlConnection.String(), nil)
	// handle("There was a problem connecting to the channel: ", err)
	// Craft a message with JOIN as the first word and
	// our nodes pubkey as the second word
	joinReq := "JOIN " + pubKey
	// fmt.Printf("\nSending: %s", joinReq)
	// Initial Connection Sends N1:PK to Coord
	_ = conn.WriteMessage(1, []byte(joinReq))
	// Conditionally validate the response
	// The response is the coordinator signature of
	// the node public key we just sent it, so here
	// we are telling karai to listen for the response
	// and consider it as the pubkeysig
	_, connectionResponse, _ := conn.ReadMessage()
	if strings.Contains(string(connectionResponse), "Welcome back") {
		fmt.Println("\nConnected")
		// keep alive?
	} else {
		if len(connectionResponse) != 128 {
			// fmt.Println("\nThe Coordinator Public Key Signature we received was not the correct length. \nIt should be 128 characters.")
			// fmt.Println("\"" + string(connectionResponse) + "\"" + " is " + string(len(connectionResponse)) + " characters long.")
			// fmt.Println("\nThere seems to be a problem: ", string(connectionResponse))
			return
		}
		// Print some things to help debug
		// fmt.Printf("\n%s\n", readMessageRecvPubKeySig)
		// fmt.Printf("\n%s\n", pubKey)
		// if err != nil {
		// 	fmt.Println("\nThere was a problem reading this message:", err)
		// 	return
		// }
		// The one issue encountered here is the sig being
		// the wrong length, so lets make sure that is 128
		if len(connectionResponse) == 128 {
			signature := string(bytes.TrimRight(connectionResponse, "\n"))
			// Printing the signature for debugging purposes
			// fmt.Printf("\nCoord Pubkey Signature: %s", signature)
			// Write a message to the coordinator requesting
			// the coordinator pubkey. Store it as a var.
			// fmt.Printf("\nSending: PUBK request for Coord pubkey...")
			_ = conn.WriteMessage(1, pubkMsg)
			_, readMessageRecvCoordPubKey, _ := conn.ReadMessage()
			coordPubkey := string(bytes.TrimRight(readMessageRecvCoordPubKey, "\n"))
			// Print the coordinator pubkey signature for debug
			// fmt.Printf("\nCoord Pubkey Signature: %s\n", readMessageRecvCoordPubKey)
			// fmt.Printf("\nReceived Coord PubKey: %s", coordPubkey)
			// fmt.Printf("\nReceived Coord Signature:\t%s", signature)
			if VerifySignedKey(pubKey, coordPubkey, signature) {
				// fmt.Println("\nCoordinator signature verified ✔️")
				n1smsg := "NSIG" + signedKey
				// Send the signed key for N1s as bytes
				// fmt.Printf("Sending NSIG message to Coordinator...\n%s", n1smsg)
				_ = conn.WriteMessage(1, []byte(n1smsg))
				_, n1sresponse, _ := conn.ReadMessage()
				hashedSigCertResponse := bytes.TrimRight(n1sresponse, "\n")
				hashedSigCertResponseNoPrefix := string(bytes.TrimLeft(hashedSigCertResponse, "CERT "))
				// fmt.Println(hashedSigCertResponseNoPrefix)
				if len(hashedSigCertResponseNoPrefix) == 128 {
					fmt.Printf("\n[%s] [%s] Certificate Granted\n", timeStamp(), conn.RemoteAddr())
					fmt.Printf("user> ")
					fmt.Printf("%s\n", pubKey)
					fmt.Printf("cert> ")
					fmt.Printf("%s\n", hashedSigCertResponseNoPrefix)
				} else {
					fmt.Printf("%v is the wrong size\n%s", len(hashedSigCertResponseNoPrefix), hashedSigCertResponseNoPrefix)
				}
			}
		} else {
			// fmt.Println("\nDrat! It failed..")
			return
		}
	}
}

// GenerateKeys Generates ed25519 keyset as strings
func GenerateKeys() *ED25519Keys {
	keys := ED25519Keys{}
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	keys.privateKey = hex.EncodeToString(privKey[0:32])
	keys.publicKey = hex.EncodeToString(pubKey)
	signedKey := ed25519.Sign(privKey, pubKey)
	keys.signedKey = hex.EncodeToString(signedKey)
	return &keys
}

// Sign Takes keys and a message to sign
func Sign(myKeys *ED25519Keys, msg string) string {
	messageBytes := []byte(msg)
	privateKey, err := hex.DecodeString(myKeys.privateKey)
	if err != nil {
		panic(err)
	}
	publicKey, err := hex.DecodeString(myKeys.publicKey)
	if err != nil {
		panic(err)
	}
	privateKey = append(privateKey, publicKey...)
	signature := ed25519.Sign(privateKey, messageBytes)
	return hex.EncodeToString(signature)
}

// SignKey Sign a set of keys
func SignKey(myKeys *ED25519Keys, publicKey string) string {
	messageBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		panic(err)
	}
	privateKey, err := hex.DecodeString(myKeys.privateKey)
	if err != nil {
		panic(err)
	}
	pubKey, err := hex.DecodeString(myKeys.publicKey)
	if err != nil {
		panic(err)
	}
	privateKey = append(privateKey, pubKey...)
	signature := ed25519.Sign(privateKey, messageBytes)
	return hex.EncodeToString(signature)
}

// VerifySignature Verifies a signature and returns true or false
func VerifySignature(publicKey string, msg string, signature string) bool {
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

// VerifySignedKey Verifies if the keys created are correct and returns boolean
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
