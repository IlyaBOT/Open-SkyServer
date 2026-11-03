package server

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/IlyaBOT/Open-SkyServer/server/go/internal/keys"
)

func TestDirectoryRestoresOnlyFreshVerifiedRecords(t *testing.T) {
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil { t.Skip("sqlite3 is not installed") }
	db := NewDatabase(filepath.Join(t.TempDir(), "skyserver.db"), sqlite)
	if err := db.EnsureSchema(); err != nil { t.Fatal(err) }
	if err := db.AddAccount("peer.test", "Peer", "test-password"); err != nil { t.Fatal(err) }
	set := &keys.Set{Credentials: testKey(t, 2048)}
	client := testKey(t, 1024)
	now := time.Now().UTC()
	credential, err := IssueCredential(set, "peer.test", client.N.FillBytes(make([]byte, 128)), now)
	if err != nil { t.Fatal(err) }
	fields, err := EncodeBlob([]Field{fieldNumber(1, 1)})
	if err != nil { t.Fatal(err) }
	hash := sha1.Sum(credential)
	message := append(hash[:], fields...)
	block := make([]byte, 128)
	start := 107 - len(message)
	block[0] = 0x4b
	for i := 1; i < start-1; i++ { block[i] = 0xbb }
	block[start-1] = 0xba
	copy(block[start:], message)
	hash = sha1.Sum(message)
	copy(block[107:127], hash[:])
	block[127] = 0xbc
	signature, err := client.PrivateOperation(block)
	if err != nil { t.Fatal(err) }
	record := append([]byte{0, 0, 1, 4}, credential...)
	record = append(record, signature...)
	if _, err := VerifySignedRecord(record, set, now); err != nil { t.Fatalf("invalid fixture: %v", err) }
	if err := db.StoreVerifiedNativeSignedRecord("peer.test", record); err != nil { t.Fatal(err) }
	stored, updated, err := db.getFreshNativeSignedRecord("PEER.TEST", time.Now().UTC(), locationRecordTTL)
	if err != nil || !bytes.Equal(stored, record) { t.Fatalf("fresh record missing: %v", err) }
	if stale, _, err := db.getFreshNativeSignedRecord("peer.test", updated.Add(locationRecordTTL), locationRecordTTL); err != nil || stale != nil { t.Fatalf("expired record returned: %v", err) }

	props := make([]byte, 8)
	binary.LittleEndian.PutUint32(props, 16)
	binary.LittleEndian.PutUint32(props[4:], 11)
	id := uint16(1)
	req := NodeCommand{Code: 0xe, Flags: 2, RequestID: &id, Fields: []Field{
		{Type: 5, ID: 0, Children: []Field{
			{Type: 3, ID: 0, Bytes: []byte("peer.test")}, fieldNumber(1, 0), fieldNumber(2, 16),
		}},
		{Type: 6, ID: 1, Bytes: props},
	}}
	directory := NewRecordDirectory(set, db)
	reply, err := directory.Handle(req, time.Now().UTC())
	if err != nil || reply == nil || len(reply.Fields) != 2 { t.Fatalf("fresh record not restored: %+v %v", reply, err) }
	if !bytes.Equal(reply.Fields[0].Children[1].Bytes, record) { t.Fatal("restored record differs from persisted record") }
	if len(directory.records) != 1 { t.Fatalf("restored cache size=%d", len(directory.records)) }
	reply, err = NewRecordDirectory(set, db).Handle(req, updated.Add(locationRecordTTL))
	if err != nil || reply == nil || len(reply.Fields) != 1 { t.Fatalf("expired record restored: %+v %v", reply, err) }
	tampered := append([]byte(nil), record...)
	tampered[264] ^= 1
	if err := db.StoreVerifiedNativeSignedRecord("peer.test", tampered); err != nil { t.Fatal(err) }
	reply, err = NewRecordDirectory(set, db).Handle(req, time.Now().UTC())
	if err != nil || reply == nil || len(reply.Fields) != 1 { t.Fatalf("invalid signature restored: %+v %v", reply, err) }
}

func TestDirectoryRecordSurvivesStaggeredLogin(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	d := NewRecordDirectory(nil,nil)
	d.records["peer.test"] = recordEntry{value: []byte{1, 2, 3}, expires: now.Add(locationRecordTTL), id: 42}
	props := make([]byte, 8)
	binary.LittleEndian.PutUint32(props, 16)
	binary.LittleEndian.PutUint32(props[4:], 11)
	id := uint16(1)
	req := NodeCommand{Code: 0xe, Flags: 2, RequestID: &id, Fields: []Field{
		{Type: 5, ID: 0, Children: []Field{
			{Type: 3, ID: 0, Bytes: []byte("peer.test")}, fieldNumber(1, 0), fieldNumber(2, 16),
		}},
		{Type: 6, ID: 1, Bytes: props},
	}}
	if locationRecordTTL < time.Hour { t.Fatalf("location lease too short: %s", locationRecordTTL) }
	reply, err := d.Handle(req, now.Add(30*time.Minute))
	if err != nil { t.Fatal(err) }
	if reply == nil || len(reply.Fields) != 2 || reply.Fields[0].Type != 5 || reply.Fields[0].ID != 0 {
		t.Fatalf("staggered peer lookup lost live record: %+v", reply)
	}
	reply, err = d.Handle(req, now.Add(locationRecordTTL+time.Second))
	if err != nil { t.Fatal(err) }
	if reply == nil || len(reply.Fields) != 1 { t.Fatalf("expired peer record still advertised: %+v", reply) }
}
