package server

import (
	"os/exec"
	"path/filepath"
	"testing"
)

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
	if err := db.AddContact("native.test", "transport.test"); err != nil {
		t.Fatal(err)
	}
	contacts, err := db.GetContacts("native.test")
	if err != nil || len(contacts) != 1 || contacts[0].Login != "transport.test" {
		t.Fatalf("contacts=%+v err=%v", contacts, err)
	}
	term := DirectoryTerm{Property: 0, Comparison: 0, Text: "transport.test"}
	found, err := db.SearchNativeDirectory([]DirectoryTerm{term})
	if err != nil || len(found) != 1 || found[0].Login != "transport.test" {
		t.Fatalf("directory=%+v err=%v", found, err)
	}
	snapshot, err := db.GetNativeDocuments("native.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Documents) == 0 {
		t.Fatal("contact document was not projected")
	}
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
