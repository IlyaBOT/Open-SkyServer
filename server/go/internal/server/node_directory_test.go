package server

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestDirectoryRecordSurvivesStaggeredLogin(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	d := NewRecordDirectory(nil)
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
