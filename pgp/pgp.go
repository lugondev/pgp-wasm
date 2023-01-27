package pgp

import (
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

type RsaArmor struct {
	Passphrase []byte `json:"passphrase"`

	Private string `json:"private"`
	Pubkey  string `json:"pubkey"`
}

func (k *RsaArmor) SignPlainTextWithPrivate(plainText string) (*crypto.PGPSignature, error) {
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

func (k *RsaArmor) EncryptPlainTextWithPubkey(plainText string) (string, error) {
	return helper.EncryptMessageArmored(k.Pubkey, plainText)
}

func (k *RsaArmor) DecryptArmored(pgpMsg string) (string, error) {
	return helper.DecryptMessageArmored(k.Private, k.Passphrase, pgpMsg)
}

func (k *RsaArmor) VerifySignature(msg, signature string) (bool, error) {
	message := crypto.NewPlainMessage([]byte(msg))
	pgpSignature, err := crypto.NewPGPSignatureFromArmored(signature)
	if err != nil {
		return false, err
	}
	publicKeyObj, err := crypto.NewKeyFromArmored(k.Pubkey)
	if err != nil {
		return false, err
	}
	signingKeyRing, err := crypto.NewKeyRing(publicKeyObj)
	if err != nil {
		return false, err
	}
	err = signingKeyRing.VerifyDetached(message, pgpSignature, crypto.GetUnixTime())
	if err != nil {
		return false, err
	}
	return true, nil
}
