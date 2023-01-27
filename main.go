package main

import (
	"encoding/json"
	"fmt"
	"pgp-wasm/pgp"
)

func main() {
	var (
		name       = "Lugon Dev"
		email      = "lugon@alphatrue.com"
		passphrase = []byte("LongSecret")
	)
	pgpRsa, err := pgp.GenerateKeyArmor(&pgp.KeyParam{
		Name:       name,
		Email:      email,
		Passphrase: passphrase,
	})
	if err != nil {
		panic(err)
	}

	jsonData, err := json.Marshal(pgpRsa)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(jsonData))
}
