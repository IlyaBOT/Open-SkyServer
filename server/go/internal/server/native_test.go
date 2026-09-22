package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/IlyaBOT/Open-SkyServer/server/go/internal/keys"
)

func testKey(t *testing.T, bits int) *keys.Key {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return &keys.Key{
		N:    new(big.Int).Set(k.N),
		E:    big.NewInt(int64(k.E)),
		D:    new(big.Int).Set(k.D),
		Size: bits / 8,
	}
}

func TestCommunityCredentialRoundTrip(t *testing.T) {
	set := &keys.Set{Credentials: testKey(t, 2048)}
	client := make([]byte, 128)
	if _, err := rand.Read(client); err != nil {
		t.Fatal(err)
	}
	client[0] |= 0x80
	client[len(client)-1] |= 1
	now := time.Date(2026, 9, 22, 20, 0, 0, 0, time.UTC)
	credential, err := IssueCredential(set, "native.test", client, now)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := RecoverCredential(set, credential)
	if err != nil {
		t.Fatal(err)
	}
	user, err := Required(fields, 3, 0)
	if err != nil || string(user.Bytes) != "native.test" {
		t.Fatalf("credential username=%q err=%v", user.Bytes, err)
	}
	modulus, err := Required(fields, 4, 1)
	if err != nil || !bytes.Equal(modulus.Bytes, client) {
		t.Fatal("credential client modulus mismatch")
	}
}

func TestProtectedResponseRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	payload := []byte{0x41, 0x00}
	record, err := ProtectResponse(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(record) != len(payload)+7 || record[0] != 0x17 || record[1] != 3 || record[2] != 1 {
		t.Fatalf("invalid response envelope: %x", record)
	}
	if int(binary.BigEndian.Uint16(record[3:5])) != len(payload)+2 {
		t.Fatal("response length mismatch")
	}
	cipher := record[5 : len(record)-2]
	crc := CRC32Skype(cipher)
	if record[len(record)-2] != byte(crc) || record[len(record)-1] != byte(crc>>8) {
		t.Fatal("response CRC mismatch")
	}
	clear, err := LoginAESCTR(key, cipher, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clear, payload) {
		t.Fatalf("AES response mismatch: %x", clear)
	}
}
