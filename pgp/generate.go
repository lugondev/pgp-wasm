package pgp

import (
	"encoding/hex"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

type KeyParam struct {
	Name       string `json:"name"`
	Email      string `json:"email"`
	Passphrase []byte `json:"passphrase"`

	keyType string
	rsaBits int
}

func GenerateKey(params *KeyParam) (*KeyRSA, error) {
	// KeyRSA, string
	rsaKey, err := helper.GenerateKey(params.Name, params.Email, params.Passphrase, params.keyType, params.rsaBits)
	if err != nil {
		return nil, err
	}

	// KeyRSA, hex
	return &KeyRSA{
		Passphrase: params.Passphrase,

		Private: rsaKey,
		Hex:     hex.EncodeToString([]byte(rsaKey)),
	}, nil
}
