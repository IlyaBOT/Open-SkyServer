package server

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/IlyaBOT/Open-SkyServer/server/go/internal/keys"
)

type NodeCommand struct {
	Code uint32
	Flags byte
	RequestID *uint16
	Fields []Field
}
type NodeFrame struct {
	Sequence uint16
	IsAcknowledgment bool
	Commands []NodeCommand
}

func decodeNodeVarint(data []byte,at *int)(uint32,error){return readVarint(data,at)}

func DecodeNodeFrame(frame []byte)(NodeFrame,error){
	var out NodeFrame
	if len(frame)<4{return out,fmt.Errorf("short node frame")}
	at:=0;size,e:=decodeNodeVarint(frame,&at);if e!=nil{return out,e};if at+int(size>>1)!=len(frame)||size>>1==0{return out,fmt.Errorf("node length mismatch")}
	if size&1!=0{
		if len(frame)-at!=3||frame[at]!=1{return out,fmt.Errorf("invalid node ack")}
		out.IsAcknowledgment=true;out.Sequence=binary.BigEndian.Uint16(frame[at+1:]);return out,nil
	}
	if len(frame)-at<2{return out,fmt.Errorf("missing node sequence")};out.Sequence=binary.BigEndian.Uint16(frame[at:]);at+=2
	for at<len(frame){
		if len(out.Commands)>=64{return out,fmt.Errorf("too many node commands")}
		bodyLen,e:=decodeNodeVarint(frame,&at);if e!=nil{return out,e}
		enc,e:=decodeNodeVarint(frame,&at);if e!=nil{return out,e}
		if bodyLen>uint32(len(frame)-at){return out,fmt.Errorf("invalid node command length")}
		end:=at+int(bodyLen)
		cmd:=NodeCommand{Code:enc>>3,Flags:byte(enc&7)};if cmd.Flags>3{return out,fmt.Errorf("invalid node flags")}
		if cmd.Flags==2||cmd.Flags==3{if at+2>end{return out,fmt.Errorf("missing request id")};v:=binary.BigEndian.Uint16(frame[at:]);at+=2;cmd.RequestID=&v}
		if at>=end{return out,fmt.Errorf("missing node command payload")};fields,used,e:=DecodeBlob(frame[at:end]);if e!=nil{return out,e};if used!=end-at{return out,fmt.Errorf("trailing node command fields")};cmd.Fields=fields;at=end;out.Commands=append(out.Commands,cmd)
	}
	return out,nil
}
func EncodeNodeFrame(seq uint16,commands ...NodeCommand)([]byte,error){
	var body bytes.Buffer;var s [2]byte;binary.BigEndian.PutUint16(s[:],seq);body.Write(s[:])
	for _,c:=range commands{
		payload,e:=EncodeBlob(c.Fields);if e!=nil{return nil,e}
		hasRequest:=c.Flags==2||c.Flags==3
		if hasRequest!=(c.RequestID!=nil){return nil,fmt.Errorf("invalid node request-id flags")}
		bodyLen:=len(payload);if hasRequest{bodyLen+=2}
		if e:=writeVarint(&body,uint32(bodyLen));e!=nil{return nil,e}
		if e:=writeVarint(&body,c.Code<<3|uint32(c.Flags));e!=nil{return nil,e}
		if hasRequest{var r [2]byte;binary.BigEndian.PutUint16(r[:],*c.RequestID);body.Write(r[:])}
		body.Write(payload)
	}
	var out bytes.Buffer;if e:=writeVarint(&out,uint32(body.Len()<<1));e!=nil{return nil,e};out.Write(body.Bytes());if out.Len()>16384{return nil,fmt.Errorf("node frame too large")};return out.Bytes(),nil
}
func AcknowledgeNode(seq uint16)([]byte,error){var out bytes.Buffer;if e:=writeVarint(&out,7);e!=nil{return nil,e};out.WriteByte(1);var b [2]byte;binary.BigEndian.PutUint16(b[:],seq);out.Write(b[:]);return out.Bytes(),nil}

type FrameBuffer struct{ pending []byte }
func (f *FrameBuffer) Append(data []byte)([][]byte,error){
	var frames [][]byte
	for _,b:=range data{
		f.pending=append(f.pending,b);size:=uint32(0);prefix:=0;complete:=false
		for prefix<len(f.pending)&&prefix<3{v:=f.pending[prefix];size|=uint32(v&127)<<uint(7*prefix);prefix++;if v&128==0{complete=true;break}}
		if !complete{if prefix>=3{return nil,fmt.Errorf("oversized Skype TCP length prefix")};continue}
		total:=prefix+int(size>>1);if total<=prefix||total>16384{return nil,fmt.Errorf("invalid Skype TCP frame size")}
		if len(f.pending)==total{frames=append(frames,append([]byte(nil),f.pending...));f.pending=f.pending[:0]}
	}
	return frames,nil
}
func (f *FrameBuffer) Partial()bool{return len(f.pending)!=0}

func SlotReply(req NodeCommand,local *net.TCPAddr)(*NodeCommand,error){
	if req.Code!=6{return nil,nil};hasSlot:=false;for _,f:=range req.Fields{hasSlot=hasSlot||(f.Type==0&&f.ID==0)};if !hasSlot{return nil,nil}
	if req.Flags!=2||req.RequestID==nil||len(req.Fields)!=2{return nil,fmt.Errorf("invalid slot request header")};slot,e:=Required(req.Fields,0,0);if e!=nil{return nil,e};count,e:=Required(req.Fields,0,5);if e!=nil{return nil,e}
	if slot.Number>=2048||count.Number==0||count.Number>32{return nil,fmt.Errorf("invalid directory slot/count")};if local==nil||local.IP.To4()==nil||local.IP.IsUnspecified()||local.Port==0{return nil,fmt.Errorf("missing concrete directory endpoint")}
	ep:=make([]byte,6);copy(ep,local.IP.To4());binary.BigEndian.PutUint16(ep[4:],uint16(local.Port))
	return &NodeCommand{Code:8,Flags:3,RequestID:req.RequestID,Fields:[]Field{{Type:5,ID:6,Children:[]Field{{Type:2,ID:3,Bytes:ep},fieldNumber(0,slot.Number),fieldNumber(7,1)}}}},nil
}

func publicRaw(block,mod []byte)([]byte,error){
	if len(block)!=len(mod){return nil,fmt.Errorf("RSA block length mismatch")};n:=new(big.Int).SetBytes(mod);m:=new(big.Int).SetBytes(block);if m.Cmp(n)>=0{return nil,fmt.Errorf("RSA block outside modulus")};r:=new(big.Int).Exp(m,big.NewInt(65537),n);out:=make([]byte,len(mod));r.FillBytes(out);return out,nil
}

type SignedRecord struct{Username string;Fields []Field}
func VerifySignedRecord(value []byte,ks *keys.Set,now time.Time)(*SignedRecord,error){
	if len(value)<392||len(value)>8192||!bytes.Equal(value[:4],[]byte{0,0,1,4}){return nil,fmt.Errorf("unsupported signed directory record envelope")}
	credential:=append([]byte(nil),value[4:264]...);identity,e:=RecoverCredential(ks,credential);if e!=nil{return nil,e};u,e:=Required(identity,3,0);if e!=nil{return nil,e};username:=string(u.Bytes);if !validUsername(username){return nil,fmt.Errorf("invalid directory identity")}
	ex,e:=Required(identity,0,4);if e!=nil{return nil,e};if !now.Before(time.Unix(int64(ex.Number)*60,0)){return nil,fmt.Errorf("expired directory credential")}
	m,e:=Required(identity,4,1);if e!=nil{return nil,e};if len(m.Bytes)!=128||m.Bytes[0]&0x80==0||m.Bytes[127]&1==0{return nil,fmt.Errorf("invalid directory client key")}
	block,e:=publicRaw(value[264:392],m.Bytes);if e!=nil{return nil,e};if block[127]!=0xbc{return nil,fmt.Errorf("invalid record recovery trailer")}
	start:=1;if block[0]==0x4b{for start<107&&block[start]==0xbb{start++};if start>=106||block[start]!=0xba{return nil,fmt.Errorf("invalid record recovery padding")};start++}else if block[0]!=0x4a&&block[0]!=0x6a{return nil,fmt.Errorf("unsupported record recovery header")}
	if (block[0]==0x6a)!=(len(value)>392)||107-start<=20{return nil,fmt.Errorf("invalid record recovery extent")}
	msg:=append([]byte(nil),block[start:107]...);msg=append(msg,value[392:]...);h:=sha1.Sum(msg);if !bytes.Equal(h[:],block[107:127]){return nil,fmt.Errorf("invalid record digest")};hc:=sha1.Sum(credential);if len(msg)<20||!bytes.Equal(hc[:],msg[:20]){return nil,fmt.Errorf("invalid record credential binding")}
	fields,used,e:=DecodeBlob(msg[20:]);if e!=nil{return nil,e};if used!=len(msg)-20{return nil,fmt.Errorf("trailing directory record data")}
	rec:=&SignedRecord{username,fields};logDetailedSignedRecord(rec,len(value));return rec,nil
}

// Skype 4.2 does not republish its signed location within the initial minutes of a session.
const locationRecordTTL = 6 * time.Hour

type recordEntry struct{value []byte;expires time.Time;id uint32}
type RecordDirectory struct{ks *keys.Set;db *Database;mu sync.Mutex;records map[string]recordEntry}
func NewRecordDirectory(ks *keys.Set,db *Database)*RecordDirectory{return &RecordDirectory{ks:ks,db:db,records:map[string]recordEntry{}}}
func (d *RecordDirectory) expire(now time.Time){for k,v:=range d.records{if !v.expires.After(now){delete(d.records,k)}}}
func (d *RecordDirectory) restore(username string,now time.Time)error{
	if d.ks==nil||d.db==nil{return nil}
	key:=strings.ToLower(username)
	d.mu.Lock();d.expire(now);_,cached:=d.records[key];d.mu.Unlock();if cached{return nil}
	value,updated,e:=d.db.getFreshNativeSignedRecord(username,now,locationRecordTTL);if e!=nil{return e};if len(value)==0{return nil}
	rec,e:=VerifySignedRecord(value,d.ks,now);if e!=nil{log.Printf("directory ignored stored record user=%q: %v",username,e);return nil}
	if !strings.EqualFold(rec.Username,username){log.Printf("directory ignored stored record for mismatched user=%q",username);return nil}
	sum:=sha256.Sum256(value);candidate:=recordEntry{append([]byte(nil),value...),updated.Add(locationRecordTTL),binary.LittleEndian.Uint32(sum[:4])}
	d.mu.Lock();d.expire(now);if _,ok:=d.records[key];!ok&&len(d.records)<1024{d.records[key]=candidate;log.Printf("directory restored user=%q expires=%s",rec.Username,candidate.expires.UTC().Format(time.RFC3339))};d.mu.Unlock()
	return nil
}
func (d *RecordDirectory) Handle(req NodeCommand,now time.Time)(*NodeCommand,error){
	if req.Code!=0xc&&req.Code!=0xe{return nil,nil};if req.Flags!=2||req.RequestID==nil{return nil,fmt.Errorf("invalid directory request header")}
	var result []Field
	if req.Code==0xc{
		if d.ks==nil{return nil,nil};if len(req.Fields)!=1{return nil,fmt.Errorf("unsupported directory publication fields")};v,e:=Required(req.Fields,4,0xb);if e!=nil{return nil,e};rec,e:=VerifySignedRecord(v.Bytes,d.ks,now);if e!=nil{return nil,e}
		if d.db!=nil{if e:=d.db.StoreVerifiedNativeSignedRecord(rec.Username,v.Bytes);e!=nil{return nil,e}}
		sum:=sha256.Sum256(v.Bytes);id:=binary.LittleEndian.Uint32(sum[:4]);d.mu.Lock();d.expire(now);if len(d.records)>=1024{if _,ok:=d.records[strings.ToLower(rec.Username)];!ok{d.mu.Unlock();return nil,fmt.Errorf("directory capacity reached")}};d.records[strings.ToLower(rec.Username)]=recordEntry{append([]byte(nil),v.Bytes...),now.Add(locationRecordTTL),id};count:=len(d.records);d.mu.Unlock();log.Printf("directory stored user=%q ttl=%s records=%d",rec.Username,locationRecordTTL,count)
	}else{
		if len(req.Fields)!=2&&len(req.Fields)!=3{return nil,nil};var excluded []byte;if len(req.Fields)==3{x,e:=Required(req.Fields,6,2);if e!=nil{return nil,e};excluded=x.Bytes;if len(excluded)>400||len(excluded)%4!=0{return nil,fmt.Errorf("invalid excluded identifiers")}}
		q,e:=Required(req.Fields,5,0);if e!=nil{return nil,e};props,e:=Required(req.Fields,6,1);if e!=nil{return nil,e};if len(q.Children)!=3||len(props.Bytes)!=8||binary.LittleEndian.Uint32(props.Bytes)!=16||binary.LittleEndian.Uint32(props.Bytes[4:])!=11{return nil,nil}
		u,e:=Required(q.Children,3,0);if e!=nil{return nil,e};off,e:=Required(q.Children,0,1);if e!=nil{return nil,e};lim,e:=Required(q.Children,0,2);if e!=nil{return nil,e};username:=string(u.Bytes);if !validUsername(username)||lim.Number==0||lim.Number>100{return nil,fmt.Errorf("invalid location query")}
		if e:=d.restore(username,now);e!=nil{return nil,e}
		d.mu.Lock();d.expire(now);ent,ok:=d.records[strings.ToLower(username)];count:=len(d.records);omit:=false;if off.Number==0&&ok{for i:=0;i<len(excluded);i+=4{omit=omit||binary.LittleEndian.Uint32(excluded[i:])==ent.id};if !omit{result=append(result,Field{Type:5,ID:0,Children:[]Field{fieldNumber(0x10,ent.id),{Type:4,ID:0xb,Bytes:append([]byte(nil),ent.value...)}}})}};d.mu.Unlock();log.Printf("directory lookup user=%q offset=%d limit=%d hit=%t excluded=%t records=%d",username,off.Number,lim.Number,ok,omit,count);result=append(result,fieldNumber(1,0))
	}
	return &NodeCommand{Code:req.Code+1,Flags:3,RequestID:req.RequestID,Fields:result},nil
}
