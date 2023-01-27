package pgp

import "github.com/ProtonMail/gopenpgp/v2/crypto"

type KeyRSA struct {
	Passphrase []byte `json:"passphrase"`

	Private string `json:"rsa"`
	Hex     string `json:"hex_rsa"`
}

func (k *KeyRSA) SignPlainText(plainText string) (*crypto.PGPSignature, error) {
	var message = crypto.NewPlainMessage([]byte(plainText))

	privateKeyObj, err := crypto.NewKeyFromArmored(k.Private)
	if err != nil {
		return nil, err
	}
	unlockedKeyObj, err := privateKeyObj.Unlock(k.Passphrase)
	if err != nil {
		return nil, err
	}
	signingKeyRing, err := crypto.NewKeyRing(unlockedKeyObj)
	if err != nil {
		return nil, err
	}

	return signingKeyRing.SignDetached(message)
}
