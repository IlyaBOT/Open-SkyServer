package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/IlyaBOT/Open-SkyServer/server/go/internal/keys"
)

type AuthServer struct {
	DB *Database
	Keys *keys.Set
	Access *AccessPolicy
	Host string
	Port int
	Once bool
	RealSkype bool
	sem chan struct{}
}

func (s *AuthServer) addr()string{return net.JoinHostPort(s.Host,fmt.Sprint(s.Port))}
func (s *AuthServer) Run(ctx context.Context)error{
	ln,e:=net.Listen("tcp4",s.addr());if e!=nil{return e};defer ln.Close();s.sem=make(chan struct{},32);log.Printf("auth listening on %s",s.addr())
	go func(){<-ctx.Done();ln.Close()}()
	for {
		c,e:=ln.Accept();if e!=nil{if ctx.Err()!=nil{return nil};return e}
		host,_,_:=net.SplitHostPort(c.RemoteAddr().String());if s.Access!=nil&&!s.Access.Allows(net.ParseIP(host)){c.Close();continue}
		select{case s.sem<-struct{}{}:default:c.Close();continue}
		run:=func(){defer func(){<-s.sem;c.Close()}();if e:=s.handle(c);e!=nil{log.Printf("auth session %s failed: %v",c.RemoteAddr(),e)}}
		if s.Once{run();return nil};go run()
	}
}
func readSome(c net.Conn,min,max int)([]byte,error){out:=make([]byte,max);n:=0;for n<min{r,e:=c.Read(out[n:]);n+=r;if e!=nil{if e==io.EOF{break};return nil,e};if r==0{break}};return out[:n],nil}
func readExact(c net.Conn,n int)([]byte,error){b:=make([]byte,n);_,e:=io.ReadFull(c,b);return b,e}

func (s *AuthServer) handle(c net.Conn)error{
	_ = c.SetDeadline(time.Now().Add(10*time.Second))
	hello,e:=readSome(c,48,1024);if e!=nil{return e};if len(hello)<48{log.Printf("short auth TCP probe %s: %d bytes",c.RemoteAddr(),len(hello));return nil}
	dh,e:=NewDHSession(hello);if e!=nil{return e};if _,e=c.Write(dh.ServerHello);e!=nil{return e};h,e:=readExact(c,8);if e!=nil{return e};if !dh.VerifyClientHash(h){return fmt.Errorf("DH384 client hash mismatch")}
	if !s.RealSkype{return s.handleDirect(c,dh,nil)}
	_ = c.SetReadDeadline(time.Now().Add(500*time.Millisecond));buf:=make([]byte,4096);n,e:=c.Read(buf);_ = c.SetReadDeadline(time.Now().Add(10*time.Second))
	if e==nil&&n>0{first:=append([]byte(nil),buf[:n]...);if looksDirect(dh.SharedSecret,first){return s.handleDirect(c,dh,first)};return fmt.Errorf("post-DH data did not match reconstructed direct RC4")}
	if ne,ok:=e.(net.Error);e!=nil&&!(ok&&ne.Timeout()){return e}
	log.Printf("auth transport selected: stock Skype")
	return s.HandleStock(c,dh,nil,false)
}

func looksDirect(secret,encrypted []byte)bool{
	c,e:=newRC4(secret);if e!=nil{return false};clear:=make([]byte,len(encrypted));c.XORKeyStream(clear,encrypted);p:=[]byte{0x16,3,1};for i:=0;i<len(clear)&&i<len(p);i++{if clear[i]!=p[i]{return false}};return true
}
func IsAccountRecordPrefix(secret,encrypted []byte)bool{
	if len(encrypted)<5{return false};c,e:=newRC4(secret);if e!=nil{return false};p:=make([]byte,len(encrypted));c.XORKeyStream(p,encrypted);n:=int(binary.BigEndian.Uint16(p[3:5]));return p[0]==0x16&&p[1]==3&&p[2]==1&&n>=192&&n<=16384
}

func (s *AuthServer) HandleStock(c net.Conn,dh *DHSession,first []byte,ackAlready bool)error{
	if !ackAlready{if _,e:=c.Write(dh.ServerHash);e!=nil{return e}}
	rc,e:=newRC4(dh.SharedSecret);if e!=nil{return e};frames,e:=readEncryptedFrames(c,rc,2,first);if e!=nil{return e};if len(frames)!=2||frames[0][0]!=0x16||frames[1][0]!=0x17||len(frames[0])<=5||len(frames[1])<=7{return fmt.Errorf("unexpected stock Skype login frame sequence")}
	if s.Keys==nil{return fmt.Errorf("no community private keys configured")}
	req,e:=ParseNativeLogin(frames[0],frames[1],s.Keys);if e!=nil{return e};valid,e:=s.DB.ValidateNativePasswordHash(req.Username,req.PasswordDigest);if e!=nil{return e};if !valid{return fmt.Errorf("native password rejected")}
	var payload []byte
	switch {
	case req.Operation==0x4278: payload,e=DirectoryRespond(req,s.DB)
	case req.Operation==0x139c:
		var email string;email,e=s.DB.GetAccountEmail(req.Username);if e==nil{payload,e=EmailPayload(email,req.RequestID)}
	case req.Operation==0x178e:
		var cs []Account;cs,e=s.DB.GetContacts(req.Username);if e==nil{payload,e=ContactListsPayload(len(cs)!=0,req.RequestID)}
	case (req.Operation>=0x1788&&req.Operation<=0x178c)||req.Operation==0x1792: payload,e=NativeContactRespond(req,s.DB)
	default:
		var cred []byte;cred,e=IssueCredential(s.Keys,req.Username,req.ClientPublicKey,time.Now().UTC());if e==nil{payload,e=SuccessPayload(cred,req.RequestID)}
	}
	if e!=nil{return e};response,e:=ProtectResponse(payload,req.AESKey);if e!=nil{return e};out,e:=newRC4(incrementFirst(dh.SharedSecret));if e!=nil{return e};cipher:=make([]byte,len(response));out.XORKeyStream(cipher,response);_,e=c.Write(cipher);if e==nil{log.Printf("auth ok %s operation=0x%x response=%d",req.Username,req.Operation,len(response))};return e
}

func readEncryptedFrames(c net.Conn,rc interface{XORKeyStream(dst,src []byte)},expected int,first []byte)([][]byte,error){
	var clear []byte;var frames [][]byte;offset:=0
	add:=func(enc []byte)error{b:=make([]byte,len(enc));rc.XORKeyStream(b,enc);clear=append(clear,b...);var e error;frames,offset,e=extractTLSFrames(clear,offset,frames,expected);return e}
	if len(first)>0{if e:=add(first);e!=nil{return nil,e}}
	buf:=make([]byte,4096)
	for len(frames)<expected{n,e:=c.Read(buf);if e!=nil{return nil,e};if n<=0{return nil,io.ErrUnexpectedEOF};if e:=add(buf[:n]);e!=nil{return nil,e}}
	return frames,nil
}
func extractTLSFrames(data []byte,offset int,frames [][]byte,expected int)([][]byte,int,error){
	for len(data)-offset>=5&&len(frames)<expected{typ:=data[offset];if (typ!=0x16&&typ!=0x17&&typ!=0x18)||data[offset+1]!=3||data[offset+2]!=1{return nil,offset,fmt.Errorf("invalid login frame header")};n:=5+int(binary.BigEndian.Uint16(data[offset+3:offset+5]));if n>65535{return nil,offset,fmt.Errorf("invalid login frame length")};if len(data)-offset<n{break};frames=append(frames,append([]byte(nil),data[offset:offset+n]...));offset+=n};return frames,offset,nil
}

func parseLocalAuth(frame []byte)(string,string,error){
	if len(frame)<5||frame[0]!=0x18||int(binary.BigEndian.Uint16(frame[3:5]))!=len(frame)-5{return "","",fmt.Errorf("missing local auth frame")}
	lines:=strings.Split(strings.ReplaceAll(string(frame[5:]),"\r",""),"\n");if len(lines)==0||lines[0]!="SKYSERVER-AUTH/1"{return "","",fmt.Errorf("invalid local auth marker")};vals:=map[string]string{};for _,l:=range lines[1:]{if p:=strings.IndexByte(l,'=');p>0{vals[strings.ToLower(l[:p])]=l[p+1:]}}
	decode:=func(h string)(string,error){if len(h)%2!=0{return "",fmt.Errorf("odd hex")};b:=make([]byte,len(h)/2);for i:=range b{var x byte;_,e:=fmt.Sscanf(h[i*2:i*2+2],"%02x",&x);if e!=nil{return "",e};b[i]=x};return string(b),nil}
	u,e:=decode(vals["user_hex"]);if e!=nil{return "","",e};p,e:=decode(vals["pass_hex"]);return u,p,e
}
func reconstructedResponse(payloadLen int)[]byte{
	p:=make([]byte,payloadLen);for i:=range p{p[i]=byte(i*37+0x41)};n:=payloadLen+2;r:=make([]byte,5+n);r[0]=0x17;r[1]=3;r[2]=1;binary.BigEndian.PutUint16(r[3:5],uint16(n));copy(r[5:],p);crc:=CRC32Skype(p);r[5+len(p)]=byte(crc);r[6+len(p)]=byte(crc>>8);return r
}
func (s *AuthServer) handleDirect(c net.Conn,dh *DHSession,first []byte)error{
	in,e:=newRC4(dh.SharedSecret);if e!=nil{return e};frames,e:=readEncryptedFrames(c,in,3,first);if e!=nil{return e};u,p,e:=parseLocalAuth(frames[2]);if e!=nil{return e};_,ok,e:=s.DB.ValidatePassword(u,p);if e!=nil{return e};if ok{_,_ = s.DB.CreateSession(u)}
	r:=reconstructedResponse(14);if ok{r=reconstructedResponse(285)};out,e:=newRC4(incrementFirst(dh.SharedSecret));if e!=nil{return e};cipher:=make([]byte,len(r));out.XORKeyStream(cipher,r);_,e=c.Write(cipher);return e
}

var _ = bytes.Equal
var _ sync.Mutex
