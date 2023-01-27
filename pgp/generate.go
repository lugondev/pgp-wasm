package pgp

import (
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

type KeyParam struct {
	Name       string `json:"name"`
	Email      string `json:"email"`
	Passphrase []byte `json:"passphrase"`

	keyType string
	rsaBits int
}

func GenerateKeyArmor(params *KeyParam) (*RsaArmor, error) {
	generatedKey, err := crypto.GenerateKey(params.Name, params.Email, params.keyType, params.rsaBits)
	if err != nil {
		return nil, err
	}

	if params.Passphrase != nil && len(params.Passphrase) > 0 {
		generatedKey, err = generatedKey.Lock(params.Passphrase)
		if err != nil {
			return nil, err
		}
	}

	publicKey, err := generatedKey.GetArmoredPublicKey()
	if err != nil {
		return nil, err
	}
	privateKey, err := generatedKey.Armor()
	if err != nil {
		return nil, err
	}

	// RsaArmor, hex
	return &RsaArmor{
		Passphrase: params.Passphrase,

		Private: privateKey,
		Pubkey:  publicKey,
	}, nil
}
