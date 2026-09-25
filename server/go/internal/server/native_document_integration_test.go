package server

import (
	"bytes"
	"os"
	"os/exec"
	"reflect"
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
		t.Logf("client contact fields=%s", describeFields(fields))
		record, recordErr := Required(fields, 4, 3)
		state, stateErr := Required(fields, 0, 0x7d)
		kind, kindErr := Required(fields, 0, 0x79)
		if recordErr != nil || stateErr != nil { t.Fatalf("client document missing signed record or state: %v %v", recordErr, stateErr) }
		if kindErr != nil { t.Fatal(kindErr) }
		t.Logf("signed record envelope=%t contact kind=%d authorization state=%d", len(record.Bytes) >= 4 && bytes.Equal(record.Bytes[:4], []byte{0, 0, 1, 4}), kind.Number, state.Number)
		identity, err := Required(fields, 3, 0x10)
		if err != nil { t.Fatalf("client contact document shape=%s: %v", describeFields(fields), err) }
		if string(identity.Bytes) != strings.TrimPrefix(doc.Name, "u/") { t.Fatal("client contact document identity mismatch") }
		display, err := Required(fields, 3, 0x14)
		if err != nil { t.Fatal(err) }
		generated, err := ContactDocument(Account{Login: string(identity.Bytes), DisplayName: string(display.Bytes)}, record.Bytes)
		if err != nil { t.Fatal(err) }
		generatedFields, generatedUsed, err := DecodeBlob(generated)
		if err != nil || generatedUsed != len(generated) { t.Fatalf("generated document decode: %v", err) }
		t.Logf("generated document matches client fields=%t bytes=%t wire_kind=%x generated_kind=%x", reflect.DeepEqual(generatedFields, fields), bytes.Equal(generated, doc.Body), doc.Body[0], generated[0])
	}
	if !found { t.Skip("no client-written contact document available") }
}
