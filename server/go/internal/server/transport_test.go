package server

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestNodeFramingStage41Fixtures(t *testing.T) {
	captured := []byte{0x18,0x34,0xcd,8,0x32,0x34,0xcc,0x42,0x34,0x1e,0x8c,0x63,0x1e}
	n, err := DecodeNodeFrame(captured)
	if err != nil { t.Fatal(err) }
	if n.Sequence != 0x34cd || len(n.Commands) != 1 || n.Commands[0].Code != 6 || n.Commands[0].Flags != 2 || n.Commands[0].RequestID == nil || *n.Commands[0].RequestID != 0x34cc {
		t.Fatalf("captured node frame mismatch: %+v", n)
	}
	ack, err := AcknowledgeNode(0xabcd)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(ack, []byte{7,1,0xab,0xcd}) { t.Fatalf("ack=%x", ack) }

	cmd := NodeCommand{Code:37,Flags:1,Fields:[]Field{{Type:4,ID:1,Bytes:make([]byte,300)}}}
	wire, err := EncodeNodeFrame(0xabcd, cmd)
	if err != nil { t.Fatal(err) }
	for split:=1;split<len(wire);split++ {
		fb:=&FrameBuffer{}
		a,err:=fb.Append(wire[:split]);if err!=nil{t.Fatal(err)}
		if len(a)!=0||!fb.Partial(){t.Fatalf("split %d emitted early",split)}
		b,err:=fb.Append(wire[split:]);if err!=nil{t.Fatal(err)}
		if len(b)!=1||fb.Partial(){t.Fatalf("split %d failed",split)}
	}
}

func TestCommand30EndpointRewrite(t *testing.T) {
	request:=[]byte{0x14,0x25,0x1c,5,0xf2,1,0x25,0x1b,0x42,0x2d,3}
	s:=&TCPProbeServer{}
	s.seq.Store(100)
	for _,port:=range []int{80,12350,40021,65535}{
		remote:=&net.TCPAddr{IP:net.ParseIP("192.0.2.55"),Port:51001}
		local:=&net.TCPAddr{IP:net.ParseIP("127.0.0.1"),Port:port}
		reply,ok:=s.buildCommand30Reply(request,remote,local)
		if !ok{t.Fatalf("no command-30 reply for port %d",port)}
		if reply[6]!=request[6]||reply[7]!=request[7]{t.Fatal("request sequence lost")}
		fields,used,err:=DecodeBlob(reply[8:]);if err!=nil{t.Fatal(err)}
		if used!=len(reply)-8{t.Fatal("trailing command-30 fields")}
		ep,err:=Required(fields,2,0x11);if err!=nil{t.Fatal(err)}
		if !bytes.Equal(ep.Bytes[:4],remote.IP.To4())||int(binary.BigEndian.Uint16(ep.Bytes[4:]))!=remote.Port{t.Fatalf("remote endpoint=%v",ep.Bytes)}
		parent,err:=Required(fields,0,0x10);if err!=nil{t.Fatal(err)}
		if parent.Number!=uint32(port){t.Fatalf("parent port=%d want=%d",parent.Number,port)}
	}
}

func TestDirectProbeNeedsCompleteHeader(t *testing.T) {
	if looksDirect(make([]byte,48),[]byte{0}) { t.Fatal("partial RC4 header accepted") }
}
