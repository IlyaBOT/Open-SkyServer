package server

import (
	"net"
	"testing"
)

func TestUDPPacketRoundTripFixture(t *testing.T) {
	client:=net.ParseIP("192.0.2.10")
	server:=net.ParseIP("198.51.100.20")
	clear:=[]byte{4,0xb3,4,0,1,0x42,0x15}
	packet,err:=buildUDPPacket(ip32(client),ip32(server),3,17,clear)
	if err!=nil{t.Fatal(err)}
	s:=&UDPServer{}
	reply,ok:=s.buildReply(client,server,packet)
	if !ok||len(reply)<12{t.Fatalf("UDP fixture rejected: ok=%v len=%d",ok,len(reply))}
}

func TestUDPAccessPolicy(t *testing.T) {
	p:=&AccessPolicy{nets:[]*net.IPNet{}}
	if p.Allows(net.ParseIP("127.0.0.1")){t.Fatal("empty closed policy allowed UDP peer")}
}
