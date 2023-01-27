package pgp

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDetached(t *testing.T) {
	var (
		name       = "Lugon Dev"
		email      = "lugon@alphatrue.com"
		passphrase = []byte("LongSecret")
		msg        = "Hello World"
	)
	pgpRsa, err := GenerateKey(&KeyParam{
		Name:       name,
		Email:      email,
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatal(err)
	}
	pgpSignature, err := pgpRsa.SignPlainText(msg)
	assert.NoError(t, err)
	assert.NotNil(t, pgpSignature)

	armored, err := pgpSignature.GetArmored()
	assert.NoError(t, err)
	fmt.Println("Signature:", armored)
}
