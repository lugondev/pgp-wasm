package main

import (
	"encoding/hex"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

func main() {
	var (
		name       = "Max Mustermann"
		email      = "max.mustermann@example.com"
		passphrase = []byte("LongSecret")
		rsaBits    = 2048
	)
	// RSA, string
	rsaKey, err := helper.GenerateKey(name, email, passphrase, "rsa", rsaBits)
	if err != nil {
		panic(err)
	}
	hexKey := hex.EncodeToString([]byte(rsaKey))
	fmt.Println(hexKey)

	bytesKey, err := hex.DecodeString(hexKey)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bytesKey))
}
