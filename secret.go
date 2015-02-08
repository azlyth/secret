package main

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"encoding/base64"
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/howeyc/gopass"
	"github.com/koding/kite"
	"io/ioutil"
	"log"
	"os"
)

// General values

const Author = "Peter Valdez"
const Email = "peter@nycmesh.net"
const Name = "secret"
const Usage = "Send secrets with ease."
const Version = "0.1.0"

const mysecretstring = "this is so very secret!"
const prefix = "/Users/peter/"
const secretKeyring = prefix + ".gnupg/secring.gpg"
const publicKeyring = prefix + ".gnupg/pubring.gpg"

var context *cli.Context

// Flags

var Flags = []cli.Flag{
	cli.BoolFlag{
		Name:  "verbose",
		Usage: "talks more",
	},
}

// Subcommands

var Commands = []cli.Command{
	{
		Name:   "send",
		Usage:  "Sends a secret",
		Action: handle(send),
	},
	{
		Name:   "receive",
		Usage:  "Waits for secrets",
		Action: handle(receive),
		Flags:  Flags,
	},
}

func handle(f func() error) func(*cli.Context) {
	return func(c *cli.Context) {
		// Store the context globally
		context = c

		// Run the function
		err := f()
		if err != nil {
			log.Fatal(err)
		}
	}
}

// Receive subcommand

func receive() error {
	// Create and configure the kite
	k := kite.New(Name, Version)
	k.Config.Port = 4321
	k.SetLogLevel(kite.ERROR)
	k.HandleFunc("secret", secret).DisableAuthentication()

	// Run the kite
	fmt.Println("Waiting for secrets...")
	k.Run()

	return nil
}

func secret(r *kite.Request) (interface{}, error) {
	// Retrieve the encrypted secret
	encrypted := r.Args.One().MustString()

	// Decrypt and print the secret
	decrypted, err := decryptMessage(encrypted)
	if err != nil {
		return nil, err
	}
	fmt.Println(decrypted)

	// Return an acknowledgment
	return "Received.", nil
}

// Send subcommand

func send() error {
	// Create the kite
	k := kite.New(Name, Version)

	// Connect to the server kite
	client := k.NewClient("http://localhost:4321/kite")
	client.Dial()

	// Send them a secret
	fmt.Println("Sending secret...")
	secret, err := encryptMessage(mysecretstring)
	if err != nil {
		return err
	}

	response, _ := client.Tell("secret", secret)
	fmt.Println(response.MustString())

	return nil
}

func encryptMessage(str string) (string, error) {
	// Read in public key
	keyringFileBuffer, _ := os.Open(publicKeyring)
	defer keyringFileBuffer.Close()
	entitylist, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err
	}

	// Encrypt string
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entitylist, nil, nil, nil)
	if err != nil {
		return "", err
	}
	_, err = w.Write([]byte(str))
	if err != nil {
		return "", err
	}
	err = w.Close()
	if err != nil {
		return "", err
	}

	// Encode to base64
	bytesp, err := ioutil.ReadAll(buf)
	if err != nil {
		return "", err
	}
	encstr := base64.StdEncoding.EncodeToString(bytesp)

	return encstr, nil
}

func decryptMessage(encstr string) (string, error) {
	var entity2 *openpgp.Entity
	var entitylist2 openpgp.EntityList

	// Output encrypted/encoded string
	if context.Bool("verbose") {
		fmt.Println("Encrypted Secret:", encstr)
	}

	// Open the private key file
	keyringFileBuffer2, err := os.Open(secretKeyring)
	if err != nil {
		return "", err
	}
	defer keyringFileBuffer2.Close()
	entitylist2, err = openpgp.ReadKeyRing(keyringFileBuffer2)
	if err != nil {
		return "", err
	}
	entity2 = entitylist2[0]

	// Get the passphrase and read the private key.
	// Have not touched the encrypted string yet
	if context.Bool("verbose") {
		fmt.Println("Decrypting private key using passphrase")
	}
	if !decryptKey(entity2) {
		fmt.Println("Incorrect password. Exiting.")
		return "", nil
	}
	if context.Bool("verbose") {
		fmt.Println("Finished decrypting private key using passphrase")
	}

	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encstr)
	if err != nil {
		return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entitylist2, nil, nil)
	if err != nil {
		return "", err
	}
	bytess, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	decstr := string(bytess)

	return decstr, nil
}

func decryptKey(entity *openpgp.Entity) bool {
	// Get the password
	fmt.Printf("Password: ")
	passphrase := gopass.GetPasswd()
	passphrasebyte := []byte(passphrase)

	// Decrypt the key and subkeys
	err := entity.PrivateKey.Decrypt(passphrasebyte)
	if err != nil {
		return false
	}
	for _, subkey := range entity.Subkeys {
		err := subkey.PrivateKey.Decrypt(passphrasebyte)
		if err != nil {
			return false
		}
	}

	return true
}

func main() {
	// Setup the app
	app := cli.NewApp()
	app.Name = Name
	app.Author = Author
	app.Email = Email
	app.Usage = Usage
	app.Version = Version
	app.Commands = Commands

	// Run the app
	app.Run(os.Args)
}
