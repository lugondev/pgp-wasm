package pgp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	name       = "Lugon Dev"
	email      = "lugon@alphatrue.com"
	passphrase = []byte("LongSecret")
	msg        = "Hello World"
)

func TestDetached(t *testing.T) {
	pgpRsa, err := GenerateKeyArmor(&KeyParam{
		Name:       name,
		Email:      email,
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatal(err)
	}
	pgpSignature, err := pgpRsa.SignPlainTextWithPrivate(msg)
	assert.NoError(t, err)
	assert.NotNil(t, pgpSignature)

	signature, err := pgpSignature.GetArmored()
	assert.NoError(t, err)

	// verify
	verified, err := pgpRsa.VerifySignature(msg, signature)
	assert.NoError(t, err)
	assert.True(t, verified)
}

func TestSignPubkey(t *testing.T) {
	pgpRsa, err := GenerateKeyArmor(&KeyParam{
		Name:       name,
		Email:      email,
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatal(err)
	}
	pgpMsg, err := pgpRsa.EncryptPlainTextWithPubkey(msg)
	assert.NoError(t, err)
	assert.NotEqual(t, pgpMsg, "")

	decrypted, err := pgpRsa.DecryptArmored(pgpMsg)
	assert.NoError(t, err)
	assert.Equal(t, decrypted, msg)
}
