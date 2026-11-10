package server

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"os/exec"
	"path/filepath"
	"testing"
)

// This is a synthetic native document test, not evidence of a client upload.
func TestNativeAvatarDocumentPersistence(t *testing.T) {
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 is not installed")
	}
	path := filepath.Join(t.TempDir(), "avatar.db")
	db := NewDatabase(path, sqlite)
	if err := db.EnsureSchema(); err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"avatar.owner", "avatar.other"} {
		if err := db.RegisterNativeAccount(user, user, user+"@example.test", NativePasswordDigest(user, "test-only")); err != nil {
			t.Fatal(err)
		}
	}
	img := image.NewRGBA(image.Rect(0, 0, 96, 96))
	for y := 0; y < 96; y++ {
		for x := 0; x < 96; x++ {
			img.SetRGBA(x, y, color.RGBA{uint8(x * 2), uint8(y * 2), uint8(x ^ y), 255})
		}
	}
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, img, &jpeg.Options{Quality: 75}); err != nil {
		t.Fatal(err)
	}
	avatar := encoded.Bytes()
	checksum := CRC32Skype(avatar)
	request := func(user string, operation uint32, fields ...Field) *NativeLoginRequest {
		return &NativeLoginRequest{Username: user, Operation: operation, RequestID: 19,
			Metadata: append([]Field{{Type: 1, ID: 0x3a, Bytes: make([]byte, 8)}}, fields...)}
	}
	put := request("avatar.owner", 0x1789, Field{Type: 3, ID: 0x34, Bytes: []byte("p/avatar")},
		Field{Type: 4, ID: 0x33, Bytes: avatar}, fieldNumber(0x32, checksum))
	putResponse, err := NativeContactRespond(put, db)
	if err != nil {
		t.Fatal(err)
	}
	header, _ := decodeNativeAccountResponse(t, putResponse)
	status, err := Required(header, 0, 1)
	if err != nil || status.Number != 0x1450 {
		t.Fatalf("put status=%+v err=%v", status, err)
	}

	// A second instance has no in-memory knowledge of the first upload.
	db = NewDatabase(path, sqlite)
	manifest, err := NativeContactRespond(request("avatar.owner", 0x178c), db)
	if err != nil {
		t.Fatal(err)
	}
	_, fields := decodeNativeAccountResponse(t, manifest)
	checksums, err := Required(fields, 4, 0x35)
	if err != nil || len(checksums.Bytes)%4 != 0 {
		t.Fatalf("invalid manifest: %v", err)
	}
	found := false
	for i := 0; i < len(checksums.Bytes); i += 4 {
		found = found || binary.BigEndian.Uint32(checksums.Bytes[i:i+4]) == checksum
	}
	if !found {
		t.Fatal("persisted avatar missing from fresh-instance manifest")
	}
	fetch := request("avatar.owner", 0x1788, fieldNumber(0x32, checksum))
	response, err := NativeContactRespond(fetch, db)
	if err != nil {
		t.Fatal(err)
	}
	_, fields = decodeNativeAccountResponse(t, response)
	document, err := Required(fields, 5, 0x37)
	if err != nil {
		t.Fatal(err)
	}
	name, err := Required(document.Children, 3, 0x34)
	if err != nil || string(name.Bytes) != "p/avatar" {
		t.Fatalf("wrong document name: %+v err=%v", name, err)
	}
	body, err := Required(document.Children, 4, 0x33)
	if err != nil || !bytes.Equal(body.Bytes, avatar) {
		t.Fatal("avatar bytes changed after database round trip")
	}
	if _, err := jpeg.Decode(bytes.NewReader(body.Bytes)); err != nil {
		t.Fatalf("returned avatar is not the original valid JPEG: %v", err)
	}
	if _, err := ProtectResponse(response, make([]byte, 32)); err != nil {
		t.Fatalf("avatar response does not fit native account transport: %v", err)
	}
	if _, err := NativeContactRespond(request("avatar.other", 0x1788, fieldNumber(0x32, checksum)), db); err == nil {
		t.Fatal("another account fetched the owner's private document")
	}
	put.Metadata[len(put.Metadata)-1].Number ^= 1
	if _, err := NativeContactRespond(put, db); err == nil {
		t.Fatal("corrupt avatar checksum accepted")
	}
	if _, err := NativeContactRespond(fetch, db); err != nil {
		t.Fatalf("rejected upload damaged the persisted avatar: %v", err)
	}
	remove := request("avatar.owner", 0x178a, Field{Type: 3, ID: 0x34, Bytes: []byte("p/avatar")})
	if _, err := NativeContactRespond(remove, db); err != nil {
		t.Fatal(err)
	}
	if _, err := NativeContactRespond(fetch, db); err == nil {
		t.Fatal("deleted avatar was still returned")
	}
}
