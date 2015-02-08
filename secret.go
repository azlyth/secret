package main

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"encoding/base64"
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/howeyc/gopass"
	"io/ioutil"
	"log"
	"os"
)

// Commmand line arguments

// create gpg keys with
// $ gpg --gen-key
// ensure you correct paths and passphrase

const mysecretstring = "this is so very secret!"
const prefix = "/Users/peter/"
const secretKeyring = prefix + ".gnupg/secring.gpg"
const publicKeyring = prefix + ".gnupg/pubring.gpg"

// Command-line commands
var commands = []cli.Command{
	{
		Name:   "send",
		Usage:  "Sends a secret",
		Action: send,
	},
	{
		Name:   "encrypt",
		Usage:  "Encrypts a secret",
		Action: encrypt,
	},
}

func send(c *cli.Context) {
	_, err := fmt.Println("Sending.")
	if err != nil {
		exit(err)
	}
}

func encrypt(c *cli.Context) {
	err := encryptMessage()
	if err != nil {
		exit(err)
	}
}

func exit(err error) {
	log.Fatal(err)
}

func encryptMessage() error {
	fmt.Println("Secret:", mysecretstring)

	// Read in public key
	keyringFileBuffer, _ := os.Open(publicKeyring)
	defer keyringFileBuffer.Close()
	entitylist, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return err
	}

	// Encrypt string
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entitylist, nil, nil, nil)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(mysecretstring))
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}

	// Encode to base64
	bytesp, err := ioutil.ReadAll(buf)
	if err != nil {
		return err
	}
	encstr := base64.StdEncoding.EncodeToString(bytesp)

	// Output encrypted/encoded string
	//if options.Verbose {
	//fmt.Println("Encrypted Secret:", encstr)
	//}

	// Here is where I would transfer the encrypted string to someone else
	// but we'll just decrypt it in the same code

	// Init some vars
	var entity2 *openpgp.Entity
	var entitylist2 openpgp.EntityList

	// Open the private key file
	keyringFileBuffer2, err := os.Open(secretKeyring)
	if err != nil {
		return err
	}
	defer keyringFileBuffer2.Close()
	entitylist2, err = openpgp.ReadKeyRing(keyringFileBuffer2)
	if err != nil {
		return err
	}
	entity2 = entitylist2[0]

	// Get the passphrase and read the private key.
	// Have not touched the encrypted string yet
	//if options.Verbose {
	//fmt.Println("Decrypting private key using passphrase")
	//}
	if !decryptKey(entity2) {
		fmt.Println("Incorrect password. Exiting.")
		return nil
	}
	//for !decryptKey(entity2) {
	//}
	//if options.Verbose {
	//fmt.Println("Finished decrypting private key using passphrase")
	//}

	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encstr)
	if err != nil {
		return err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entitylist2, nil, nil)
	if err != nil {
		return err
	}
	bytess, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return err
	}
	decstr := string(bytess)

	// Should be done
	fmt.Println("Decrypted Secret:", decstr)

	return nil
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
	app.Name = "secret"
	app.Author = "Peter Valdez"
	app.Email = "peter@nycmesh.net"
	app.Usage = "Send secrets with ease."
	app.Version = "0.1.0"
	app.Commands = commands

	// Run the app
	app.Run(os.Args)
}
