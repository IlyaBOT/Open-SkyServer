package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/IlyaBOT/Open-SkyServer/server/go/internal/keys"
	"github.com/IlyaBOT/Open-SkyServer/server/go/internal/skypecrypto"
)

var supernodeProbePayload=[]byte{0x42,0x6a,0xc5,0x8d,0x1e,0xbc,0x40,0x53,0xbb,0xcd}

type TCPProbeServer struct {
	Host string
	Ports []int
	AdvertiseIP net.IP
	Access *AccessPolicy
	Auth *AuthServer
	Keys *keys.Set
	DB *Database
	records *RecordDirectory
	sem chan struct{}
	seq atomic.Uint32
}
func (s *TCPProbeServer) Run(ctx context.Context){s.records=NewRecordDirectory(s.Keys,s.DB);s.sem=make(chan struct{},128);s.seq.Store(uint32(time.Now().UnixNano()));for _,p:=range s.Ports{go s.runPort(ctx,p)}}
func (s *TCPProbeServer) nextSeq()uint16{return uint16(s.seq.Add(1))}
func (s *TCPProbeServer) runPort(ctx context.Context,port int){
	ln,e:=net.Listen("tcp4",net.JoinHostPort(s.Host,fmt.Sprint(port)));if e!=nil{log.Printf("tcp probe could not bind %s:%d: %v",s.Host,port,e);return};defer ln.Close();go func(){<-ctx.Done();ln.Close()}();log.Printf("tcp probe listening on %s:%d",s.Host,port)
	for{c,e:=ln.Accept();if e!=nil{if ctx.Err()!=nil{return};continue};host,_,_:=net.SplitHostPort(c.RemoteAddr().String());if s.Access!=nil&&!s.Access.Allows(net.ParseIP(host)){c.Close();continue};select{case s.sem<-struct{}{}:go func(){defer func(){<-s.sem;c.Close()}();if e:=s.handle(c);e!=nil{log.Printf("tcp probe %s error: %v",c.RemoteAddr(),e)}}();default:c.Close()}}
}
func looksFallback(b []byte)bool{
	if len(b)<8{return false};u:=strings.ToUpper(string(b[:minInt(len(b),8)]));for _,p:=range []string{"GET ","POST ","HEAD ","CONNECT ","OPTIONS "}{if strings.HasPrefix(u,p){return false}};return !(len(b)>=3&&b[0]==0x16&&b[1]==3)
}
func minInt(a,b int)int{if a<b{return a};return b}
func (s *TCPProbeServer) handle(c net.Conn)error{
	_ = c.SetDeadline(time.Now().Add(10*time.Second));buf:=make([]byte,2048);n,e:=c.Read(buf);if e!=nil{return e};if !looksFallback(buf[:n]){return nil}
	for n<48{r,e:=c.Read(buf[n:48]);n+=r;if e!=nil{return e}}
	dh,e:=NewDHSession(buf[:n]);if e!=nil{return e};if _,e=c.Write(dh.ServerHello);e!=nil{return e};h,e:=readExact(c,8);if e!=nil{return e};if !dh.VerifyClientHash(h){return fmt.Errorf("bootstrap DH hash mismatch")};if _,e=c.Write(dh.ServerHash);e!=nil{return e}
	var early []byte;_ = c.SetReadDeadline(time.Now().Add(500*time.Millisecond));tmp:=make([]byte,5);nn,e:=io.ReadFull(c,tmp);_ = c.SetReadDeadline(time.Now().Add(10*time.Second));if e==nil&&nn==5{early=tmp;if s.Auth!=nil&&IsAccountRecordPrefix(dh.SharedSecret,early){return s.Auth.HandleStock(c,dh,early,true)}}else if e!=nil{if ne,ok:=e.(net.Error);!ok||!ne.Timeout(){if e!=io.EOF&&e!=io.ErrUnexpectedEOF{return e}}}
	rc,e:=skypecrypto.NewSession();if e!=nil{return e};defer rc.Close();hello,e:=rc.MakeServerHandshake(dh.SharedSecret);if e!=nil{return e};if _,e=c.Write(hello);e!=nil{return e}
	first:=make([]byte,16);copy(first,early);if _,e=io.ReadFull(c,first[len(early):]);e!=nil{return e};clear,e:=rc.DecryptClientHandshake(dh.SharedSecret,first);if e!=nil{return e};if len(clear)<16||clear[6]!=0||clear[7]!=0||clear[8]!=0||clear[9]!=1||clear[10]!=0||clear[11]!=0||clear[12]!=0||clear[15]!=3{return fmt.Errorf("invalid bootstrap RC4 handshake signature")}
	if e:=activateNodeConnection(c);e!=nil{return e}
	fb:=&FrameBuffer{};garbage:=true;probeSent:=false
	process:=func(frames [][]byte)error{
		for _,frame:=range frames{
			if garbage{garbage=false;continue};parsed,e:=DecodeNodeFrame(frame);if e!=nil{return e};if parsed.IsAcknowledgment{continue};ack:=false
			for _,cmd:=range parsed.Commands{
				if cmd.Flags==1{ack=true}
				if cmd.Code==0xc||cmd.Code==0xe{log.Printf("node directory %s code=0x%x flags=%d fields=%s",c.RemoteAddr(),cmd.Code,cmd.Flags,describeFields(cmd.Fields))}
				if detailedDebugEnabled.Load()&&cmd.Code!=0xc&&cmd.Code!=0xe{
					log.Printf("detailed node command %s code=0x%x flags=%d fields=%s",c.RemoteAddr(),cmd.Code,cmd.Flags,describeFields(cmd.Fields))
				}
				if rep,e:=s.records.Handle(cmd,time.Now().UTC());e!=nil{return e}else if rep!=nil{if cmd.Code==0xc||cmd.Code==0xe{log.Printf("node directory %s reply=0x%x fields=%s",c.RemoteAddr(),rep.Code,describeFields(rep.Fields))};wire,e:=EncodeNodeFrame(s.nextSeq(),*rep);if e!=nil{return e};if e=s.sendEncrypted(c,rc,wire);e!=nil{return e}}
				local:=c.LocalAddr().(*net.TCPAddr);lip:=local.IP;if s.AdvertiseIP!=nil&&s.AdvertiseIP.To4()!=nil{lip=s.AdvertiseIP};dir:=&net.TCPAddr{IP:lip,Port:local.Port}
				if rep,e:=SlotReply(cmd,dir);e!=nil{return e}else if rep!=nil{wire,e:=EncodeNodeFrame(s.nextSeq(),*rep);if e!=nil{return e};if e=s.sendEncrypted(c,rc,wire);e!=nil{return e}}
			}
			if ack{wire,_:=AcknowledgeNode(parsed.Sequence);if e:=s.sendEncrypted(c,rc,wire);e!=nil{return e}}
			if !probeSent{if rep,ok:=s.supernodeReply(frame,c);ok{if e:=s.sendEncrypted(c,rc,rep);e!=nil{return e};probeSent=true}}
		};return nil
	}
	frames,e:=fb.Append(clear[14:16]);if e!=nil{return e};if e=process(frames);e!=nil{return e}
	for{if e:=c.SetReadDeadline(time.Now().Add(120*time.Second));e!=nil{return e};n,e:=c.Read(buf);if e!=nil{if e==io.EOF{return nil};if ne,ok:=e.(net.Error);ok&&ne.Timeout(){return nil};return e};dec,e:=rc.Decrypt(buf[:n]);if e!=nil{return e};frames,e:=fb.Append(dec);if e=process(frames);e!=nil{return e}}
}
func activateNodeConnection(c net.Conn)error{
	if e:=c.SetWriteDeadline(time.Time{});e!=nil{return e}
	return c.SetReadDeadline(time.Now().Add(120*time.Second))
}
func (s *TCPProbeServer) sendEncrypted(c net.Conn,rc *skypecrypto.Session,clear []byte)error{enc,e:=rc.Encrypt(clear);if e!=nil{return e};if e=c.SetWriteDeadline(time.Now().Add(10*time.Second));e!=nil{return e};_,e=c.Write(enc);return e}

func looksLegacyFrame(p []byte)bool{if len(p)<9{return false};return int(p[0]>>1)+1==len(p)&&int(p[3])==len(p)-6&&p[8]==0x42}
func (s *TCPProbeServer) supernodeReply(req []byte,c net.Conn)([]byte,bool){
	if !looksLegacyFrame(req){return nil,false};hi,lo:=req[4],req[5]
	if hi==0xf2&&lo==1{return s.command30Reply(req,c)}
	if hi!=0xca||lo!=4{return nil,false};prev:=binary.BigEndian.Uint16(req[6:8]);r:=make([]byte,8+len(supernodeProbePayload));r[0]=byte((len(r)-1)<<1);binary.BigEndian.PutUint16(r[1:3],s.nextSeq());r[3]=byte(len(supernodeProbePayload)+2);r[4]=0xdb;r[5]=4;binary.BigEndian.PutUint16(r[6:8],prev);copy(r[8:],supernodeProbePayload);return r,true
}
func (s *TCPProbeServer) command30Reply(req []byte,c net.Conn)([]byte,bool){
	remote,ok:=c.RemoteAddr().(*net.TCPAddr);if !ok{return nil,false}
	local,ok:=c.LocalAddr().(*net.TCPAddr);if !ok{return nil,false}
	return s.buildCommand30Reply(req,remote,local)
}

func (s *TCPProbeServer) buildCommand30Reply(req []byte,remote,local *net.TCPAddr)([]byte,bool){
	if !looksLegacyFrame(req)||req[4]!=0xf2||req[5]!=1{return nil,false}
	if remote==nil||remote.IP.To4()==nil||remote.Port<1||remote.Port>65535{return nil,false}
	if local==nil||local.IP.To4()==nil||local.Port<1||local.Port>65535{return nil,false}
	observedIP:=remote.IP.To4()
	if s.AdvertiseIP!=nil&&s.AdvertiseIP.To4()!=nil&&remote.IP.IsPrivate(){
		observedIP=s.AdvertiseIP.To4()
		if detailedDebugEnabled.Load(){log.Printf("detailed command30 hairpin correction remote=%s advertise-ip=%s observed-port=%d",remote.IP.String(),observedIP.String(),remote.Port)}
	}
	const hexReply="D121FB0100004106000B34000CECD193D0050211750325C706940010D5B802002C01062100"
	raw:=make([]byte,len(hexReply)/2);for i:=range raw{fmt.Sscanf(hexReply[i*2:i*2+2],"%02x",&raw[i])}
	fields,used,e:=DecodeBlob(raw[6:]);if e!=nil||used!=len(raw)-6{return nil,false}
	endpointFound:=false;portFound:=false
	for i:=range fields{
		if fields[i].Type==2&&fields[i].ID==0x11&&len(fields[i].Bytes)==6{copy(fields[i].Bytes,observedIP);binary.BigEndian.PutUint16(fields[i].Bytes[4:],uint16(remote.Port));endpointFound=true}
		if fields[i].Type==0&&fields[i].ID==0x10{fields[i].Number=uint32(local.Port);portFound=true}
	}
	if !endpointFound||!portFound{return nil,false}
	updated,e:=EncodeBlob(fields);if e!=nil{return nil,false};reply:=make([]byte,8+len(updated));if len(reply)>128{return nil,false}
	reply[0]=byte((len(reply)-1)<<1);binary.BigEndian.PutUint16(reply[1:3],s.nextSeq());reply[3]=byte(len(updated)+2);reply[4]=0xfb;reply[5]=1;binary.BigEndian.PutUint16(reply[6:8],binary.BigEndian.Uint16(req[6:8]));copy(reply[8:],updated);return reply,true
}
func DefaultTCPPorts(authPort,apiPort int)[]int{p:=[]int{80,443,12350,12351,13392};for i:=40001;i<=40036;i++{p=append(p,i)};out:=uniquePorts(p);r:=out[:0];for _,v:=range out{if v!=authPort&&v!=apiPort{r=append(r,v)}};return r}
