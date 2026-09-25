package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"os/exec"
	"path/filepath"
	"strings"
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


func TestDescribeFieldsIsStructuralOnly(t *testing.T) {
	fields := []Field{
		{Type: 3, ID: 4, Bytes: []byte("secret-user")},
		{Type: 4, ID: 5, Bytes: []byte("0123456789abcdef")},
		{Type: 0, ID: 2, Number: 0xdeadbeef},
		{Type: 5, ID: 0x20, Children: []Field{{Type: 3, ID: 0x23, Bytes: []byte("private-query")}}},
	}
	got := describeFields(fields)
	if got != "3:4[11],4:5[16],0:2,5:20{1}" {
		t.Fatalf("unexpected structural description: %q", got)
	}
	for _, secret := range []string{"secret-user", "0123456789abcdef", "deadbeef", "private-query"} {
		if strings.Contains(got, secret) {
			t.Fatalf("structural description leaked value %q: %q", secret, got)
		}
	}
}


func decodeNativeAccountResponse(t *testing.T, payload []byte) ([]Field, []Field) {
	t.Helper()
	header, used, err := DecodeBlob(payload)
	if err != nil { t.Fatal(err) }
	body, used2, err := DecodeBlob(payload[used:])
	if err != nil { t.Fatal(err) }
	if used+used2 != len(payload) { t.Fatal("trailing native account response bytes") }
	return header, body
}

func TestNativeContactInboxFlow(t *testing.T) {
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil { t.Skip("sqlite3 is not installed") }
	db := NewDatabase(filepath.Join(t.TempDir(), "skyserver.db"), sqlite)
	if err := db.EnsureSchema(); err != nil { t.Fatal(err) }
	if err := db.AddAccount("native.test", "Native Test", "native-password"); err != nil { t.Fatal(err) }
	if err := db.AddAccount("transport.test", "Transport Test", "test-password"); err != nil { t.Fatal(err) }

	send := &NativeLoginRequest{Username:"native.test",Operation:0x1784,RequestID:11,Metadata:[]Field{
		{Type:3,ID:0x27,Bytes:[]byte("transport.test")},
		fieldNumber(0x22,7),
		{Type:3,ID:0x26,Bytes:[]byte("native.test")},
		{Type:3,ID:4,Bytes:[]byte("native.test")},
		fieldNumber(0x0e,123),
	}}
	payload, err := NativeContactInboxRespond(send, db)
	if err != nil { t.Fatal(err) }
	header, body := decodeNativeAccountResponse(t, payload)
	status, _ := Required(header,0,1); rid, _ := Required(header,0,2)
	if status.Number != 0x1068 || rid.Number != 11 || len(body) != 0 { t.Fatalf("send response status=%x rid=%d body=%v",status.Number,rid.Number,body) }
	contacts, err := db.GetContacts("native.test")
	if err != nil || len(contacts)!=1 || contacts[0].Login!="transport.test" { t.Fatalf("sender contact projection=%+v err=%v",contacts,err) }

	poll := &NativeLoginRequest{Username:"transport.test",Operation:0x1780,RequestID:12,Metadata:[]Field{
		fieldNumber(0x2d,0),{Type:3,ID:4,Bytes:[]byte("transport.test")},
	}}
	payload, err = NativeContactInboxRespond(poll, db)
	if err != nil { t.Fatal(err) }
	header, body = decodeNativeAccountResponse(t, payload)
	status,_ = Required(header,0,1)
	if status.Number!=0x1450 { t.Fatalf("poll callback rejects status %x",status.Number) }
	next, err := Required(body,0,0x2e)
	if err != nil || next.Number!=1 { t.Fatalf("poll pending flag=%d err=%v",next.Number,err) }

	fetch := &NativeLoginRequest{Username:"transport.test",Operation:0x1781,RequestID:13,Metadata:[]Field{
		fieldNumber(0x2d,0x3b9aca28),{Type:3,ID:4,Bytes:[]byte("transport.test")},
	}}
	if _,err = NativeContactInboxRespond(fetch, db); err == nil || !strings.Contains(err.Error(),"not implemented") { t.Fatalf("unverified inbox event accepted: %v",err) }

	payload, err = NativeContactInboxRespond(poll, db)
	if err != nil { t.Fatal(err) }
	_, body = decodeNativeAccountResponse(t, payload)
	if len(body)!=1 { t.Fatalf("unacknowledged request disappeared: %+v",body) }
	stillPending,err:=db.NextNativeContactRequest("transport.test")
	if err!=nil||stillPending==nil||stillPending.DeliveredUTC!="" { t.Fatalf("fetch incorrectly acknowledged request: %+v err=%v",stillPending,err) }

	spoof := &NativeLoginRequest{Username:"native.test",Operation:0x1784,RequestID:14,Metadata:[]Field{
		{Type:3,ID:0x27,Bytes:[]byte("transport.test")},fieldNumber(0x22,1),
		{Type:3,ID:0x26,Bytes:[]byte("evil.test")},{Type:3,ID:4,Bytes:[]byte("native.test")},
	}}
	if _, err := NativeContactInboxRespond(spoof, db); err == nil || !strings.Contains(err.Error(),"sender mismatch") {
		t.Fatalf("spoofed contact request err=%v",err)
	}

	if err := db.MarkNativeContactRequestDelivered("transport.test", stillPending.ID); err != nil { t.Fatal(err) }
	payload, err = NativeContactInboxRespond(fetch, db)
	if err != nil { t.Fatal(err) }
	header, body = decodeNativeAccountResponse(t, payload)
	status, _ = Required(header,0,1)
	count, err := Required(body,0,0x2f)
	if err != nil || status.Number!=0x1450 || len(body)!=1 || count.Number!=0 { t.Fatalf("empty fetch status=%x body=%+v err=%v",status.Number,body,err) }
}
