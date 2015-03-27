package main

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/azlyth/mdns"
	"github.com/codegangsta/cli"
	"github.com/howeyc/gopass"
	"github.com/koding/kite"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// General values
const LogLevel = kite.FATAL

const Author = "Peter Valdez"
const Email = "peter@nycmesh.net"
const Name = "secret"
const Usage = "Send secrets with ease."
const Version = "0.1.0"

var currentUser *user.User
var context *cli.Context
var entity *openpgp.Entity
var entityList openpgp.EntityList
var secretKeyring, publicKeyring string

// Convenience
var InternalAddrs []string
var InvalidPrefixes []string

// Flags
var Flags = []cli.Flag{
	cli.BoolFlag{
		Name:  "verbose",
		Usage: "print verbose output",
	},
}

// Subcommands
var Commands = []cli.Command{
	{
		Name:      "send",
		ShortName: "s",
		Usage:     "Sends a secret",
		Action:    handle(send),
	},
	{
		Name:      "receive",
		ShortName: "r",
		Usage:     "Waits for secrets",
		Action:    handle(receive),
		Flags:     Flags,
	},
}

func handle(f func() error) func(*cli.Context) {
	return func(c *cli.Context) {
		// Store the context globally
		context = c

		// Run the function
		err := f()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
}

// Receive subcommand
func receive() error {
	// Decrypt the key we'll be using to decrypt messages
	err := decryptKey()
	if err != nil {
		return errors.New("Unable to decrypt key.")
	}

	// Create and configure the kite
	k := kite.New("secret", Version)
	k.Config.Port = 4321
	k.HandleFunc("secret", secret).DisableAuthentication()
	k.HandleFunc("identify", identify).DisableAuthentication()

	// Prepare the kite
	k.SetLogLevel(LogLevel)
	k.Config.Region = "secret"
	k.Config.Username = "secret"
	k.Config.Environment = "secret"
	if err != nil {
		return err
	}

	// Get the interface and IPs that'll be used
	iface, err := autoSelectInterface()
	if err != nil {
		return err
	}
	ips, err := getIPsFromInterface(iface, true)
	if err != nil {
		return err
	}

	// Register the mdns service
	host, _ := os.Hostname()
	info := []string{"Sharing secrets."}
	service, err := mdns.NewMDNSService(host, "_secret._tcp", "", "", 4321, ips, info)
	if err != nil {
		return err
	}

	server, _ := mdns.NewServer(&mdns.Config{Zone: service, Iface: &iface})
	defer server.Shutdown()

	// Run the kite
	fmt.Println("Waiting for secrets...")
	k.Run()

	return nil
}

func identify(r *kite.Request) (interface{}, error) {
	// Open the file
	buf, err := ioutil.ReadFile(publicKeyring)
	if err != nil {
		return nil, err
	}

	// Encode the contents of the file to base64
	str := base64.StdEncoding.EncodeToString(buf)

	return str, nil
}

func secret(r *kite.Request) (interface{}, error) {
	// Retrieve the encrypted secret
	encrypted := r.Args.One().MustString()

	// Decrypt and print the secret
	decrypted, err := decryptMessage(encrypted)
	if err != nil {
		return nil, err
	}
	fmt.Printf("From %s: %s\n", r.Client.Name, decrypted)

	// Return an acknowledgment
	return "Received.", nil
}

// Return true if s is prefixed by any of the prefixes
func prefixedByAny(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func getIPsFromInterface(iface net.Interface, ignoreInternal bool) ([]net.IP, error) {
	// Get the addresses
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	// Get the IPs from the Addrs
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		// Ignore internal addresses
		if ignoreInternal && prefixedByAny(addr.String(), InternalAddrs) {
			continue
		}

		// Convert to IP
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

func autoSelectInterface() (net.Interface, error) {
	// Get the interfaces
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
	}

	// Get the list of addressable IPs
	for _, iface := range allInterfaces {
		// Ignore certain interfaces
		if prefixedByAny(iface.Name, InvalidPrefixes) {
			continue
		}

		// Get the interface IPs
		ips, err := getIPsFromInterface(iface, true)
		if err != nil {
			return net.Interface{}, err
		}

		// Return if any valid IPs retrieved
		if len(ips) > 0 {
			return iface, nil
		}
	}

	err = errors.New("Unable to automatically choose an IP address.")
	return net.Interface{}, err
}

func selectIPs() ([]net.IP, error) {
	// Get the interfaces
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// Filter out the ones with no addresses
	choices := make([]net.Interface, 0, 4)
	for _, iface := range allInterfaces {
		// Get the addresses
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		// The interface is a valid choice if it has addresses
		if len(addrs) > 0 {
			choices = append(choices, iface)
		}
	}

	// Error if there are no interfaces
	if len(choices) == 0 {
		err = errors.New("No interfaces with addresses to listen on.")
		return nil, err
	}

	// Display the choices
	fmt.Println("- Your network interfaces -")
	for i, choice := range choices {
		ips, err := getIPsFromInterface(choice, false)
		if err != nil {
			return nil, err
		}

		fmt.Println(strconv.Itoa(i), "-", choice.Name, ips)
	}

	// Gather the user's input
	choice := -1
	for choice < 0 || choice >= len(choices) {
		fmt.Println("\nListen on which? (Enter a number)")
		fmt.Print("> ")
		_, err = fmt.Scanf("%d", &choice)
		if err != nil {
			return nil, err
		}
	}

	// Get the interface addresses
	ips, err := getIPsFromInterface(choices[choice], false)
	if err != nil {
		return nil, err
	}

	return ips, nil
}

// Send subcommand
func send() error {
	// Retrieve the argument
	if len(context.Args()) != 1 {
		return errors.New("Invalid number of arguments.")
	}
	secret := context.Args().First()

	// Find secret peers on the network
	entriesCh := make(chan *mdns.ServiceEntry, 4)
	mdns.Lookup("_secret._tcp", entriesCh)
	close(entriesCh)
	var e *mdns.ServiceEntry
	for entry := range entriesCh {
		e = entry
	}

	// Create the kite
	k := kite.New(currentUser.Username, Version)
	k.SetLogLevel(LogLevel)

	// Connect to the peer
	client := k.NewClient(fmt.Sprintf("http://%s:%d/kite", e.AddrV4, e.Port))
	client.Dial()

	// Retrieve the public key
	response, _ := client.Tell("identify")
	str := response.MustString()
	buf, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	reader := bytes.NewReader(buf)

	// Send them a secret
	encrypted, err := encryptMessage(reader, secret)
	if err != nil {
		return err
	}
	response, _ = client.Tell("secret", encrypted)
	fmt.Println("Secret sent.")

	return nil
}

func encryptMessage(publicKey io.Reader, str string) (string, error) {
	// Read in public key
	entityList, err := openpgp.ReadKeyRing(publicKey)
	if err != nil {
		return "", err
	}

	// Encrypt string
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, nil, nil, nil)
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
	// Decode the base64 string
	dec, err := base64.StdEncoding.DecodeString(encstr)
	if err != nil {
		return "", err
	}

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(dec), entityList, nil, nil)
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

func decryptKey() error {
	// Open the private key file
	keyringFileBuffer, err := os.Open(secretKeyring)
	if err != nil {
		return err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return err
	}
	entity = entityList[0]

	// Get the password
	passphrase := os.Getenv("SECRET_PASSWORD")
	passphrasebyte := []byte(passphrase)
	if passphrase == "" {
		fmt.Printf("Enter your PGP key password: ")
		passphrasebyte = gopass.GetPasswd()
		fmt.Println()
	}

	// Decrypt the key and subkeys
	err = entity.PrivateKey.Decrypt(passphrasebyte)
	if err != nil {
		return err
	}
	for _, subkey := range entity.Subkeys {
		err = subkey.PrivateKey.Decrypt(passphrasebyte)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	// Disable the log
	log.SetOutput(ioutil.Discard)

	// Setup the filenames
	currentUser, _ = user.Current()
	prefix := currentUser.HomeDir
	secretKeyring = fmt.Sprintf("%s/.gnupg/secring.gpg", prefix)
	publicKeyring = fmt.Sprintf("%s/.gnupg/pubring.gpg", prefix)

	// Setup the convenience values
	InvalidPrefixes = []string{"docker", "vbox", "awdl"}
	InternalAddrs = []string{"127.0.0.1/8", "fe80::1/64", "::1/128"}

	// Setup the app
	app := cli.NewApp()
	app.Name = Name
	app.Email = Email
	app.Usage = Usage
	app.Author = Author
	app.Version = Version
	app.Commands = Commands

	// Run the app
	app.Run(os.Args)
}
