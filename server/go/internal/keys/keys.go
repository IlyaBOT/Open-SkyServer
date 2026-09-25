package keys

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

type rsaKeyValue struct {
	Modulus  string `xml:"Modulus"`
	Exponent string `xml:"Exponent"`
	D        string `xml:"D"`
}

type Key struct {
	N    *big.Int
	E    *big.Int
	D    *big.Int
	Size int
	mod  []byte
	exp  []byte
}

type Set struct {
	Login                  *Key
	Credentials            *Key
	LoginFingerprint       string
	CredentialsFingerprint string
}

func decodeRequired(text, name, path string) ([]byte, error) {
	if text == "" {
		return nil, fmt.Errorf("%s: %s is missing", path, name)
	}
	b, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("%s: invalid %s: %w", path, name, err)
	}
	return b, nil
}

func readXML(path string, private bool, wantBytes int) (*Key, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > 16384 {
		return nil, fmt.Errorf("%s: RSA key file is too large", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(data, []byte("<!DOCTYPE")) || bytes.Contains(data, []byte("<!ENTITY")) {
		return nil, fmt.Errorf("%s: XML entities are not allowed", path)
	}
	var x rsaKeyValue
	if err := xml.Unmarshal(data, &x); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	mod, err := decodeRequired(x.Modulus, "Modulus", path)
	if err != nil {
		return nil, err
	}
	exp, err := decodeRequired(x.Exponent, "Exponent", path)
	if err != nil {
		return nil, err
	}
	if len(mod) != wantBytes || len(exp) != 3 || exp[0] != 1 || exp[1] != 0 || exp[2] != 1 {
		return nil, fmt.Errorf("%s: expected RSA-%d/e65537", path, wantBytes*8)
	}
	k := &Key{N: new(big.Int).SetBytes(mod), E: new(big.Int).SetBytes(exp), Size: wantBytes, mod: append([]byte(nil), mod...), exp: append([]byte(nil), exp...)}
	if private {
		d, err := decodeRequired(x.D, "D", path)
		if err != nil {
			return nil, err
		}
		if len(d) == 0 || len(d) > wantBytes {
			return nil, fmt.Errorf("%s: invalid private exponent", path)
		}
		k.D = new(big.Int).SetBytes(d)
	}
	return k, nil
}

func fingerprint(mod []byte) string {
	sum := sha256.Sum256(mod)
	return hex.EncodeToString(sum[:])
}

func Load(dir string) (*Set, error) {
	loginPriv, err := readXML(filepath.Join(dir, "login.private.xml"), true, 192)
	if err != nil {
		return nil, err
	}
	loginPub, err := readXML(filepath.Join(dir, "login.public.xml"), false, 192)
	if err != nil {
		return nil, err
	}
	credPriv, err := readXML(filepath.Join(dir, "credentials.private.xml"), true, 256)
	if err != nil {
		return nil, err
	}
	credPub, err := readXML(filepath.Join(dir, "credentials.public.xml"), false, 256)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(loginPriv.mod, loginPub.mod) != 1 || subtle.ConstantTimeCompare(loginPriv.exp, loginPub.exp) != 1 {
		return nil, fmt.Errorf("login public/private pair mismatch")
	}
	if subtle.ConstantTimeCompare(credPriv.mod, credPub.mod) != 1 || subtle.ConstantTimeCompare(credPriv.exp, credPub.exp) != 1 {
		return nil, fmt.Errorf("credentials public/private pair mismatch")
	}
	set := &Set{
		Login:                  loginPriv,
		Credentials:            credPriv,
		LoginFingerprint:       fingerprint(loginPub.mod),
		CredentialsFingerprint: fingerprint(credPub.mod),
	}
	if err := set.SelfTest(); err != nil {
		return nil, err
	}
	return set, nil
}

func fixedBytes(v *big.Int, n int) ([]byte, error) {
	if v.Sign() < 0 || v.BitLen() > n*8 {
		return nil, fmt.Errorf("integer does not fit RSA block")
	}
	out := make([]byte, n)
	v.FillBytes(out)
	return out, nil
}

func (k *Key) PublicOperation(block []byte) ([]byte, error) {
	if k == nil || len(block) != k.Size {
		return nil, fmt.Errorf("incorrect raw RSA block length")
	}
	m := new(big.Int).SetBytes(block)
	if m.Cmp(k.N) >= 0 {
		return nil, fmt.Errorf("raw RSA block outside modulus")
	}
	return fixedBytes(new(big.Int).Exp(m, k.E, k.N), k.Size)
}

func (k *Key) PrivateOperation(block []byte) ([]byte, error) {
	if k == nil || k.D == nil || len(block) != k.Size {
		return nil, fmt.Errorf("incorrect raw RSA private block")
	}
	c := new(big.Int).SetBytes(block)
	if c.Cmp(k.N) >= 0 {
		return nil, fmt.Errorf("raw RSA block outside modulus")
	}
	one := big.NewInt(1)
	var r, inverse *big.Int
	for {
		candidate, err := rand.Int(rand.Reader, k.N)
		if err != nil {
			return nil, err
		}
		if candidate.Cmp(one) <= 0 {
			continue
		}
		inv := new(big.Int).ModInverse(candidate, k.N)
		if inv != nil {
			r, inverse = candidate, inv
			break
		}
	}
	re := new(big.Int).Exp(r, k.E, k.N)
	blinded := new(big.Int).Mul(c, re)
	blinded.Mod(blinded, k.N)
	m := new(big.Int).Exp(blinded, k.D, k.N)
	m.Mul(m, inverse)
	m.Mod(m, k.N)
	if new(big.Int).Exp(m, k.E, k.N).Cmp(c) != 0 {
		return nil, fmt.Errorf("RSA private operation verification failed")
	}
	return fixedBytes(m, k.Size)
}

func (s *Set) SelfTest() error {
	for name, k := range map[string]*Key{"login": s.Login, "credentials": s.Credentials} {
		challenge := make([]byte, k.Size)
		if _, err := rand.Read(challenge); err != nil {
			return err
		}
		challenge[0] = 1
		encrypted, err := k.PublicOperation(challenge)
		if err != nil {
			return fmt.Errorf("%s self-test public operation: %w", name, err)
		}
		clear, err := k.PrivateOperation(encrypted)
		if err != nil {
			return fmt.Errorf("%s self-test private operation: %w", name, err)
		}
		if subtle.ConstantTimeCompare(clear, challenge) != 1 {
			return fmt.Errorf("%s RSA pair self-test failed", name)
		}
	}
	return nil
}
