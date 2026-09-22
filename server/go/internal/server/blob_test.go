package server

import (
	"bytes"
	"testing"
)

func TestBlob41RoundTrip(t *testing.T){
	in:=[]Field{fieldNumber(1,0x1234),{Type:3,ID:2,Bytes:[]byte("hello")},{Type:4,ID:3,Bytes:[]byte{1,2,3}},{Type:5,ID:4,Children:[]Field{fieldNumber(7,9)}}}
	wire,e:=EncodeBlob(in);if e!=nil{t.Fatal(e)};out,n,e:=DecodeBlob(wire);if e!=nil{t.Fatal(e)};if n!=len(wire)||len(out)!=len(in){t.Fatalf("roundtrip len %d/%d",n,len(out))}
	wire2,e:=EncodeBlob(out);if e!=nil{t.Fatal(e)};if !bytes.Equal(wire,wire2){t.Fatalf("roundtrip differs: %x != %x",wire,wire2)}
}
func TestCRCFixture(t *testing.T){if got:=CRC32Skype([]byte("123456789"));got!=0x340bc6d9{t.Fatalf("crc=%08x",got)}}
