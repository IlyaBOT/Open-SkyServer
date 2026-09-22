package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync/atomic"

	"github.com/IlyaBOT/Open-SkyServer/server/go/internal/skypecrypto"
)

type UDPServer struct {
	Host string
	Ports []int
	AdvertiseIP net.IP
	Access *AccessPolicy
	rnd atomic.Uint32
}

func (s *UDPServer) Run(ctx context.Context){
	s.rnd.Store(uint32(uint64(0x9e3779b9)+uint64(len(s.Ports))*17))
	for _,port:=range s.Ports{go s.runPort(ctx,port)}
}
func (s *UDPServer) runPort(ctx context.Context,port int){
	ip:=net.ParseIP(s.Host);if ip==nil{log.Printf("udp invalid host %s",s.Host);return};addr:=&net.UDPAddr{IP:ip,Port:port};c,e:=net.ListenUDP("udp4",addr);if e!=nil{log.Printf("udp probe could not bind %s:%d: %v",s.Host,port,e);return};defer c.Close();go func(){<-ctx.Done();c.Close()}();log.Printf("udp probe listening on %s:%d",s.Host,port)
	buf:=make([]byte,65535)
	for{n,remote,e:=c.ReadFromUDP(buf);if e!=nil{if ctx.Err()!=nil{return};continue};if s.Access!=nil&&!s.Access.Allows(remote.IP){continue};serverIP:=s.AdvertiseIP;if serverIP==nil||serverIP.To4()==nil{serverIP=ip};if serverIP==nil||serverIP.IsUnspecified(){log.Printf("udp %d: --advertise-ip required with wildcard bind",port);continue};reply,ok:=s.buildReply(remote.IP,serverIP,buf[:n]);if ok{_,_=c.WriteToUDP(reply,remote)}}
}
func ip32(ip net.IP)uint32{v:=ip.To4();if v==nil{v=net.IPv4(127,0,0,1)};return binary.BigEndian.Uint32(v)}
func crcWords(words ...uint32)uint32{z:=uint32(0xffffffff);for _,w:=range words{z^=w;for j:=0;j<32;j++{if z&1!=0{z=(z>>1)^0xedb88320}else{z>>=1}}};return z}
func udpIV(a,b uint32,seq uint16,rnd uint32)uint32{return crcWords(a,b,uint32(seq))^rnd}
func (s *UDPServer) nextRandom()uint32{return s.rnd.Add(0x9e3779b9)}
func udpCrypt(iv uint32,in []byte)([]byte,error){return skypecrypto.UdpCrypt(iv,in)}

func (s *UDPServer) buildReply(clientIP,serverIP net.IP,request []byte)([]byte,bool){
	if len(request)<12||request[2]!=2{return nil,false};seq:=binary.BigEndian.Uint16(request[:2]);rnd:=binary.BigEndian.Uint32(request[3:7]);want:=binary.BigEndian.Uint32(request[7:11]);enc:=request[11:];sip:=ip32(serverIP)
	candidates:=[]uint32{ip32(clientIP),0,ip32(net.IPv4(127,0,0,1))};var clear []byte;var cip uint32
	for _,candidate:=range candidates{iv:=udpIV(candidate,sip,seq,rnd);p,e:=udpCrypt(iv,enc);if e==nil&&CRC32Skype(p)==want{clear=p;cip=candidate;break}}
	if clear==nil{return nil,false};if len(clear)>=5&&clear[1]==0xda&&clear[2]==1{return nil,false}
	clearSeq:=seq-1
	for i:=0;i+3<len(clear);i++{if (clear[i]==0xe2&&clear[i+1]==2)||(clear[i]==0xaa&&clear[i+1]==3)||(clear[i]==0xca&&clear[i+1]==4)||(clear[i]==0xf2&&clear[i+1]==1){clearSeq=binary.BigEndian.Uint16(clear[i+2:i+4]);break}}
	replyClear:=[]byte{4,0xb3,4,byte(clearSeq>>8),byte(clearSeq),0x42,0x15};out,e:=buildUDPPacket(sip,cip,seq,s.nextRandom(),replyClear);if e!=nil{log.Printf("udp reply: %v",e);return nil,false};return out,true
}
func buildUDPPacket(sender,receiver uint32,seq uint16,rnd uint32,clear []byte)([]byte,error){
	enc,e:=udpCrypt(udpIV(sender,receiver,seq,rnd),clear);if e!=nil{return nil,e};p:=make([]byte,11+len(enc));binary.BigEndian.PutUint16(p[:2],seq);p[2]=2;binary.BigEndian.PutUint32(p[3:7],rnd);binary.BigEndian.PutUint32(p[7:11],CRC32Skype(clear));copy(p[11:],enc);return p,nil
}

func DefaultUDPPorts(authPort int)[]int{p:=[]int{authPort,12350,12351,13392};for i:=40001;i<=40036;i++{p=append(p,i)};return uniquePorts(p)}
func uniquePorts(in []int)[]int{seen:=map[int]bool{};out:=make([]int,0,len(in));for _,p:=range in{if p>0&&p<=65535&&!seen[p]{seen[p]=true;out=append(out,p)}};return out}
var _ = fmt.Sprint
