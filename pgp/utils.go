package pgp

import (
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
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

func IsValidPrivateAndPassphrase(private string, passphrase []byte) bool {
	privateKeyObj, err := crypto.NewKeyFromArmored(private)
	if err != nil {
		return false
	}
	_, err = privateKeyObj.Unlock(passphrase)
	if err != nil {
		return false
	}
	return true
}

func EncryptArmored(pubkey, plainText string) (string, error) {
	return helper.EncryptMessageArmored(pubkey, plainText)
}
