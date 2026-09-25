package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func xmlKey(k *rsa.PrivateKey, private bool) string {
	mod := base64.StdEncoding.EncodeToString(k.N.Bytes())
	exp := big.NewInt(int64(k.E)).Bytes()
	e := base64.StdEncoding.EncodeToString(exp)
	if !private {
		return fmt.Sprintf("<RSAKeyValue><Modulus>%s</Modulus><Exponent>%s</Exponent></RSAKeyValue>", mod, e)
	}
	d := base64.StdEncoding.EncodeToString(k.D.Bytes())
	return fmt.Sprintf("<RSAKeyValue><Modulus>%s</Modulus><Exponent>%s</Exponent><D>%s</D></RSAKeyValue>", mod, e, d)
}

func writePair(t *testing.T, dir, name string, bits int) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		suffix string
		body   string
	}{
		{"private.xml", xmlKey(k, true)},
		{"public.xml", xmlKey(k, false)},
	} {
		if err := os.WriteFile(filepath.Join(dir, name+"."+item.suffix), []byte(item.body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadAndRawRSAOperations(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "login", 1536)
	writePair(t, dir, "credentials", 2048)
	set, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if set.LoginFingerprint == "" || set.CredentialsFingerprint == "" {
		t.Fatal("missing authority fingerprints")
	}
	block := make([]byte, set.Login.Size)
	if _, err := rand.Read(block); err != nil {
		t.Fatal(err)
	}
	block[0] = 1
	cipher, err := set.Login.PublicOperation(block)
	if err != nil {
		t.Fatal(err)
	}
	clear, err := set.Login.PrivateOperation(cipher)
	if err != nil {
		t.Fatal(err)
	}
	if string(clear) != string(block) {
		t.Fatal("raw RSA round-trip mismatch")
	}
}
