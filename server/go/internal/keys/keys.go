package keys

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
)

type rsaKeyValue struct {
	Modulus  string `xml:"Modulus"`
	Exponent string `xml:"Exponent"`
	D        string `xml:"D"`
}

type Set struct {
	LoginFingerprint       string
	CredentialsFingerprint string
}

func readXML(path string, needPrivate bool, wantBytes int) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var k rsaKeyValue
	if err := xml.Unmarshal(data, &k); err != nil { return nil, fmt.Errorf("%s: %w", path, err) }
	mod, err := base64.StdEncoding.DecodeString(k.Modulus)
	if err != nil || len(mod) != wantBytes { return nil, fmt.Errorf("%s: invalid RSA modulus", path) }
	exp, err := base64.StdEncoding.DecodeString(k.Exponent)
	if err != nil || len(exp) != 3 || exp[0] != 1 || exp[1] != 0 || exp[2] != 1 {
		return nil, fmt.Errorf("%s: expected exponent 65537", path)
	}
	if needPrivate && k.D == "" { return nil, fmt.Errorf("%s: private exponent missing", path) }
	return mod, nil
}

func fingerprint(mod []byte) string {
	sum := sha256.Sum256(mod)
	return hex.EncodeToString(sum[:])
}

func Load(dir string) (*Set, error) {
	loginPriv, err := readXML(filepath.Join(dir, "login.private.xml"), true, 192)
	if err != nil { return nil, err }
	loginPub, err := readXML(filepath.Join(dir, "login.public.xml"), false, 192)
	if err != nil { return nil, err }
	credPriv, err := readXML(filepath.Join(dir, "credentials.private.xml"), true, 256)
	if err != nil { return nil, err }
	credPub, err := readXML(filepath.Join(dir, "credentials.public.xml"), false, 256)
	if err != nil { return nil, err }
	if string(loginPriv) != string(loginPub) { return nil, fmt.Errorf("login public/private modulus mismatch") }
	if string(credPriv) != string(credPub) { return nil, fmt.Errorf("credentials public/private modulus mismatch") }
	return &Set{LoginFingerprint:fingerprint(loginPub), CredentialsFingerprint:fingerprint(credPub)}, nil
}
