package server

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestIntegrationNativeContactDocumentShape(t *testing.T) {
	path := os.Getenv("SKYSERVER_INTEGRATION_DOC_DB")
	owner := os.Getenv("SKYSERVER_INTEGRATION_DOC_OWNER")
	if path == "" || owner == "" { t.Skip("set read-only integration database and owner") }
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil { t.Fatal(err) }
	db := NewDatabase(path, sqlite)
	snapshot, err := db.GetNativeDocuments(owner)
	if err != nil { t.Fatal(err) }
	found := false
	for _, doc := range snapshot.Documents {
		if !strings.HasPrefix(doc.Name, "u/") { continue }
		found = true
		fields, used, err := DecodeBlob(doc.Body)
		if err != nil { t.Fatal(err) }
		if used != len(doc.Body) { t.Fatal("trailing contact document data") }
		identity, err := Required(fields, 3, 0x10)
		if err != nil { t.Fatalf("client contact document shape=%s: %v", describeFields(fields), err) }
		if string(identity.Bytes) != strings.TrimPrefix(doc.Name, "u/") { t.Fatal("client contact document identity mismatch") }
	}
	if !found { t.Skip("no client-written contact document available") }
}
