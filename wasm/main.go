package main

import (
	"encoding/json"
	"fmt"
	"pgp-wasm/pgp"
	"syscall/js"
)

func generate() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		fmt.Println("Generating key")
		if len(args) != 3 {
			return jsErr(nil, "Invalid no of arguments passed")
		}
		name := args[0].String()
		email := args[1].String()
		passphrase := args[2].String()
		rsaArmor, err := pgp.GenerateKeyArmor(&pgp.KeyParam{
			Name:       name,
			Email:      email,
			Passphrase: []byte(passphrase),
		})
		if err != nil {
			return jsErr(err, "Cannot generate key")
		}
		jsonData, err := json.Marshal(rsaArmor)
		if err != nil {
			return jsErr(err, "Cannot marshal key")
		}

		return fmt.Sprintf(`{"status": "%s","data": %v}`, "success", string(jsonData))
	})
}

func main() {
	fmt.Println("Go Web Assembly - PGP")

	js.Global().Set("generateKey", generate())

	<-make(chan bool)
}
