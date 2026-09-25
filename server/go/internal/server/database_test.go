package server

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"testing"
)

func testSignedRecord() []byte {
	record := make([]byte, 392)
	copy(record, []byte{0, 0, 1, 4})
	return record
}

func TestNativeContactDocumentUpdatesMembership(t *testing.T) {
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil { t.Skip("sqlite3 is not installed") }
	db := NewDatabase(filepath.Join(t.TempDir(), "skyserver.db"), sqlite)
	if err := db.EnsureSchema(); err != nil { t.Fatal(err) }
	if err := db.AddAccount("owner.test", "Owner", "owner-password"); err != nil { t.Fatal(err) }
	if err := db.AddAccount("peer.test", "Peer", "peer-password"); err != nil { t.Fatal(err) }
	body, err := ContactDocument(Account{Login: "peer.test", DisplayName: "Peer"}, testSignedRecord())
	if err != nil { t.Fatal(err) }
	if _, err := db.PutNativeDocument("owner.test", "u/other.test", body, CRC32Skype(body)); err == nil {
		t.Fatal("mismatched contact document accepted")
	}
	if _, err := db.PutNativeDocument("owner.test", "u/peer.test", body, CRC32Skype(body)); err != nil { t.Fatal(err) }
	contacts, err := db.GetContacts("owner.test")
	if err != nil || len(contacts) != 1 || contacts[0].Login != "peer.test" { t.Fatalf("contact membership=%+v err=%v", contacts, err) }
	if err := db.AddContact("peer.test", "owner.test"); err != nil { t.Fatal(err) }
	newRecord := testSignedRecord(); newRecord[4] = 7
	if err := db.StoreVerifiedNativeSignedRecord("peer.test", newRecord); err != nil { t.Fatal(err) }
	snapshot, err := db.GetNativeDocuments("owner.test")
	if err != nil || len(snapshot.Documents) != 1 || !bytes.Equal(snapshot.Documents[0].Body, body) {
		t.Fatalf("client-written contact document was overwritten: %+v err=%v", snapshot.Documents, err)
	}
	if _, err := db.RemoveNativeDocument("owner.test", "u/peer.test"); err != nil { t.Fatal(err) }
	contacts, err = db.GetContacts("owner.test")
	if err != nil || len(contacts) != 0 { t.Fatalf("contact persisted after document deletion: %+v err=%v", contacts, err) }
}

func TestLegacyContactDocumentReplacedAfterPeerPublication(t *testing.T) {
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil { t.Skip("sqlite3 is not installed") }
	db := NewDatabase(filepath.Join(t.TempDir(), "skyserver.db"), sqlite)
	if err := db.EnsureSchema(); err != nil { t.Fatal(err) }
	if err := db.AddAccount("owner.test", "Owner", "owner-password"); err != nil { t.Fatal(err) }
	if err := db.AddAccount("peer.test", "Peer", "peer-password"); err != nil { t.Fatal(err) }
	if err := db.AddContact("owner.test", "peer.test"); err != nil { t.Fatal(err) }
	if err := db.AddContact("peer.test", "owner.test"); err != nil { t.Fatal(err) }
	legacy, err := EncodeBlob([]Field{{Type:3,ID:0x10,Bytes:[]byte("peer.test")},{Type:3,ID:0x14,Bytes:[]byte("Peer")},fieldNumber(0x79,2)})
	if err != nil { t.Fatal(err) }
	if _, err := db.PutNativeDocument("owner.test", "u/peer.test", legacy, CRC32Skype(legacy)); err != nil { t.Fatal(err) }
	if err := db.StoreVerifiedNativeSignedRecord("peer.test", testSignedRecord()); err != nil { t.Fatal(err) }
	snapshot, err := db.GetNativeDocuments("owner.test")
	if err != nil || len(snapshot.Documents) != 1 { t.Fatalf("contact documents=%+v err=%v", snapshot.Documents, err) }
	fields, used, err := DecodeBlob(snapshot.Documents[0].Body)
	if err != nil || used != len(snapshot.Documents[0].Body) || len(fields) != 5 { t.Fatalf("legacy document not replaced: fields=%+v err=%v", fields, err) }
	if !bytes.Equal(fields[0].Bytes, testSignedRecord()) { t.Fatal("replacement lacks verified peer record") }
}

func TestDatabaseCompatibilitySurface(t *testing.T) {
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 is not installed")
	}
	db := NewDatabase(filepath.Join(t.TempDir(), "skyserver.db"), sqlite)
	if err := db.EnsureSchema(); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAccount("native.test", "Native Test", "native-password"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAccount("transport.test", "Transport Test", "test-password"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := db.ValidatePassword("native.test", "native-password"); err != nil || !ok {
		t.Fatalf("password validation ok=%v err=%v", ok, err)
	}
	digest := NativePasswordDigest("native.test", "native-password")
	if ok, err := db.ValidateNativePasswordHash("native.test", digest); err != nil || !ok {
		t.Fatalf("native verifier ok=%v err=%v", ok, err)
	}
	if err := db.SetAccountEmail("transport.test", "transport@example.test"); err != nil {
		t.Fatal(err)
	}
	// Directory lookup is deliberately independent of the contact graph.
	// A user must be searchable before either side has accepted/added the other.
	term := DirectoryTerm{Property: 0, Comparison: 0, Text: "transport.test"}
	found, err := db.SearchNativeDirectory([]DirectoryTerm{term})
	if err != nil || len(found) != 1 || found[0].Login != "transport.test" {
		t.Fatalf("directory-before-contact=%+v err=%v", found, err)
	}
	contacts, err := db.GetContacts("native.test")
	if err != nil || len(contacts) != 0 {
		t.Fatalf("pre-add contacts=%+v err=%v", contacts, err)
	}
	requestID, err := db.QueueNativeContactRequest("native.test", "transport.test", 7)
	if err != nil || requestID == 0 { t.Fatalf("queue contact request id=%d err=%v", requestID, err) }
	pendingRequest, err := db.NextNativeContactRequest("transport.test")
	if err != nil || pendingRequest == nil || pendingRequest.ID != requestID || pendingRequest.SenderLogin != "native.test" || pendingRequest.Flags != 7 {
		t.Fatalf("pending contact request=%+v err=%v", pendingRequest, err)
	}
	if err := db.MarkNativeContactRequestDelivered("transport.test", requestID); err != nil { t.Fatal(err) }
	pendingRequest, err = db.NextNativeContactRequest("transport.test")
	if err != nil || pendingRequest != nil { t.Fatalf("delivered contact request=%+v err=%v", pendingRequest, err) }
	requestID2, err := db.QueueNativeContactRequest("native.test", "transport.test", 9)
	if err != nil || requestID2 != requestID { t.Fatalf("requeued contact request id=%d want=%d err=%v", requestID2, requestID, err) }
	pendingRequest, err = db.NextNativeContactRequest("transport.test")
	if err != nil || pendingRequest == nil || pendingRequest.Flags != 9 { t.Fatalf("requeued contact request=%+v err=%v", pendingRequest, err) }
	if err := db.AddContact("native.test", "transport.test"); err != nil {
		t.Fatal(err)
	}
	contacts, err = db.GetContacts("native.test")
	if err != nil || len(contacts) != 1 || contacts[0].Login != "transport.test" {
		t.Fatalf("contacts=%+v err=%v", contacts, err)
	}
	if err := db.EnsureNativeContactDocuments("native.test"); err != nil { t.Fatal(err) }
	snapshot, err := db.GetNativeDocuments("native.test")
	if err != nil { t.Fatal(err) }
	if len(snapshot.Documents) != 0 { t.Fatal("one-sided contact gained an authorized document") }
	if err := db.AddContact("transport.test", "native.test"); err != nil { t.Fatal(err) }
	if err := db.StoreVerifiedNativeSignedRecord("transport.test", testSignedRecord()); err != nil { t.Fatal(err) }
	snapshot, err = db.GetNativeDocuments("native.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Documents) == 0 {
		t.Fatal("contact document was not projected")
	}
	fields, used, err := DecodeBlob(snapshot.Documents[0].Body)
	if err != nil || used != len(snapshot.Documents[0].Body) || len(fields) != 5 { t.Fatalf("authorized contact document fields=%+v err=%v", fields, err) }
	recordField, err := Required(fields, 4, 3)
	if err != nil || !bytes.Equal(recordField.Bytes, testSignedRecord()) { t.Fatalf("signed contact record missing: %v", err) }
	kind, err := Required(fields, 0, 0x79)
	if err != nil || kind.Number != 3 { t.Fatalf("contact kind=%d err=%v", kind.Number, err) }
	state, err := Required(fields, 0, 0x7d)
	if err != nil || state.Number != 1 { t.Fatalf("authorization state=%d err=%v", state.Number, err) }
	id, err := db.SendMessage("native.test", "transport.test", "hello")
	if err != nil || id <= 0 {
		t.Fatalf("send id=%d err=%v", id, err)
	}
	pending, err := db.ReceiveMessages("transport.test", "native.test")
	if err != nil || len(pending) != 1 || pending[0].Body != "hello" {
		t.Fatalf("receive=%+v err=%v", pending, err)
	}
	again, err := db.ReceiveMessages("transport.test", "native.test")
	if err != nil || len(again) != 0 {
		t.Fatalf("second receive=%+v err=%v", again, err)
	}
	history, err := db.GetHistory("native.test", "transport.test")
	if err != nil || len(history) != 1 || history[0].Body != "hello" {
		t.Fatalf("history=%+v err=%v", history, err)
	}
}
