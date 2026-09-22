package server

import (
	"bytes"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IlyaBOT/Open-SkyServer/server/go/internal/keys"
)

type NativeLoginRequest struct {
	Username string
	PasswordDigest []byte
	ClientPublicKey []byte
	AESKey []byte
	Operation uint32
	RequestID uint32
	Metadata []Field
}

func authPayload(record []byte,typ byte)([]byte,error){
	if len(record)<5||record[0]!=typ||record[1]!=3||record[2]!=1||int(binary.BigEndian.Uint16(record[3:5]))!=len(record)-5||len(record)>16389{return nil,fmt.Errorf("invalid native auth record")}
	return append([]byte(nil),record[5:]...),nil
}

func ParseNativeLogin(keyRecord,loginRecord []byte,ks *keys.Set)(*NativeLoginRequest,error){
	keyPayload,e:=authPayload(keyRecord,0x16);if e!=nil{return nil,e};protected,e:=authPayload(loginRecord,0x17);if e!=nil{return nil,e}
	exchange,used,e:=DecodeBlob(keyPayload);if e!=nil{return nil,e};if used!=len(keyPayload){return nil,fmt.Errorf("trailing key-exchange fields")}
	f,e:=Required(exchange,4,8);if e!=nil{return nil,e};if len(f.Bytes)!=192{return nil,fmt.Errorf("expected RSA-1536 key exchange")}
	if len(protected)<3{return nil,fmt.Errorf("short protected login record")};n:=len(protected)-2;crc:=CRC32Skype(protected[:n]);if protected[n]!=byte(crc)||protected[n+1]!=byte(crc>>8){return nil,fmt.Errorf("native login CRC mismatch")}
	material,e:=ks.Login.PrivateOperation(f.Bytes);if e!=nil{return nil,e};defer bytes.SetLength(material,0)
	if material[0]!=1{return nil,fmt.Errorf("RSA session material rejected; client may trust another authority")}
	aesKey,e:=DeriveLoginAESKey(material);if e!=nil{return nil,e};clear,e:=LoginAESCTR(aesKey,protected[:n],0);if e!=nil{return nil,e}
	account,used,e:=DecodeBlob(clear);if e!=nil{return nil,e}
	opf,e:=Required(account,0,0);if e!=nil{return nil,e};rid,e:=Required(account,0,2);if e!=nil{return nil,e};if rid.Number==0{return nil,fmt.Errorf("zero native request identifier")}
	uf,e:=Required(account,3,4);if e!=nil{return nil,e};if !utf8.Valid(uf.Bytes){return nil,fmt.Errorf("invalid native username encoding")};username:=string(uf.Bytes)
	if len(username)==0||len(username)>128||strings.IndexAny(username,"\r\n\t\x00")>=0{return nil,fmt.Errorf("invalid native username")}
	pf,e:=Required(account,4,5);if e!=nil{return nil,e};if len(pf.Bytes)!=16{return nil,fmt.Errorf("expected native MD5 password verifier")}
	if used>=len(clear){return nil,fmt.Errorf("missing client metadata")}
	meta,used2,e:=DecodeBlob(clear[used:]);if e!=nil{return nil,e};if used+used2!=len(clear){return nil,fmt.Errorf("trailing client metadata")}
	allowed:=map[uint32]bool{0x1399:true,0x13a3:true,0x139c:true,0x178e:true,0x1788:true,0x1789:true,0x178a:true,0x178b:true,0x178c:true,0x1792:true,0x4278:true}
	if !allowed[opf.Number]{return nil,fmt.Errorf("unsupported native operation 0x%x",opf.Number)}
	req:=&NativeLoginRequest{Username:username,PasswordDigest:append([]byte(nil),pf.Bytes...),AESKey:aesKey,Operation:opf.Number,RequestID:rid.Number,Metadata:meta}
	if req.Operation==0x1399||req.Operation==0x13a3{pk,e:=Required(meta,4,0x21);if e!=nil{return nil,e};if len(pk.Bytes)!=128||pk.Bytes[0]&0x80==0||pk.Bytes[127]&1==0{return nil,fmt.Errorf("expected a 1024-bit odd client RSA modulus")};req.ClientPublicKey=append([]byte(nil),pk.Bytes...)}
	return req,nil
}

func fieldNumber(id,value uint32)Field{return Field{Type:0,ID:id,Number:value}}
func unixMinutes(t time.Time)uint32{return uint32(t.UTC().Unix()/60)}

func encodeRecoveredBlock(payload []byte)([]byte,error){
	if len(payload)==0||len(payload)>234{return nil,fmt.Errorf("credential does not fit RSA recovery block")}
	b:=make([]byte,256);start:=235-len(payload)
	if start==1{b[0]=0x4a}else{b[0]=0x4b;for i:=1;i<start-1;i++{b[i]=0xbb};b[start-1]=0xba}
	copy(b[start:],payload);h:=sha1.Sum(payload);copy(b[235:255],h[:]);b[255]=0xbc;return b,nil
}

func decodeRecoveredBlock(block []byte)([]byte,error){
	if len(block)!=256||block[255]!=0xbc{return nil,fmt.Errorf("invalid credential recovery trailer")}
	start:=1;if block[0]==0x4b{for start<235&&block[start]==0xbb{start++};if start>=234||block[start]!=0xba{return nil,fmt.Errorf("invalid credential recovery padding")};start++}else if block[0]!=0x4a{return nil,fmt.Errorf("unsupported credential recovery header")}
	payload:=append([]byte(nil),block[start:235]...);h:=sha1.Sum(payload);if subtle.ConstantTimeCompare(h[:],block[235:255])!=1{return nil,fmt.Errorf("credential digest mismatch")};return payload,nil
}

func IssueCredential(ks *keys.Set,username string,clientModulus []byte,now time.Time)([]byte,error){
	if username==""||strings.IndexAny(username,"\x00\r\n\t")>=0{return nil,fmt.Errorf("invalid credential username")}
	if len(clientModulus)!=128||clientModulus[0]&0x80==0||clientModulus[127]&1==0{return nil,fmt.Errorf("expected 1024-bit client modulus")}
	payload,e:=EncodeBlob([]Field{{Type:3,ID:0,Bytes:[]byte(username)},fieldNumber(3,0),{Type:4,ID:1,Bytes:append([]byte(nil),clientModulus...)},fieldNumber(4,unixMinutes(now.Add(30*24*time.Hour))),{Type:5,ID:2,Children:[]Field{fieldNumber(9,unixMinutes(now.Add(365*24*time.Hour)))}}});if e!=nil{return nil,e}
	block,e:=encodeRecoveredBlock(payload);if e!=nil{return nil,e};sig,e:=ks.Credentials.PrivateOperation(block);if e!=nil{return nil,e};cred:=make([]byte,260);cred[3]=1;copy(cred[4:],sig);return cred,nil
}

func RecoverCredential(ks *keys.Set,credential []byte)([]Field,error){
	if len(credential)!=260||!bytes.Equal(credential[:4],[]byte{0,0,0,1}){return nil,fmt.Errorf("unsupported credential authority")}
	block,e:=ks.Credentials.PublicOperation(credential[4:]);if e!=nil{return nil,e};payload,e:=decodeRecoveredBlock(block);if e!=nil{return nil,e};f,n,e:=DecodeBlob(payload);if e!=nil{return nil,e};if n!=len(payload){return nil,fmt.Errorf("trailing credential fields")};return f,nil
}

func AccountResponse(body []byte,requestID uint32,status uint32)([]byte,error){
	if requestID==0{return nil,fmt.Errorf("zero native response identifier")};head,e:=EncodeBlob([]Field{fieldNumber(1,status),fieldNumber(2,requestID)});if e!=nil{return nil,e};return append(head,body...),nil
}
func SuccessPayload(credential []byte,requestID uint32)([]byte,error){if len(credential)!=260{return nil,fmt.Errorf("expected 260-byte credential")};b,e:=EncodeBlob([]Field{fieldNumber(0x3a,2),fieldNumber(0x3c,0),{Type:4,ID:0x24,Bytes:credential},{Type:5,ID:0x32,Children:[]Field{}}});if e!=nil{return nil,e};return AccountResponse(b,requestID,0x1068)}
func EmailPayload(email string,requestID uint32)([]byte,error){if len(email)>254||strings.IndexAny(email,"\x00\r\n\t")>=0{return nil,fmt.Errorf("invalid account email")};b,e:=EncodeBlob([]Field{{Type:3,ID:0x20,Bytes:[]byte(email)}});if e!=nil{return nil,e};return AccountResponse(b,requestID,0x1068)}
func ContactListsPayload(has bool,requestID uint32)([]byte,error){var f []Field;if has{f=[]Field{{Type:5,ID:0x38,Children:[]Field{fieldNumber(7,1)}}}};b,e:=EncodeBlob(f);if e!=nil{return nil,e};return AccountResponse(b,requestID,0x1450)}
func ProtectResponse(payload,aesKey []byte)([]byte,error){if len(payload)==0||len(payload)>16382{return nil,fmt.Errorf("invalid native response size")};cipher,e:=LoginAESCTR(aesKey,payload,1);if e!=nil{return nil,e};crc:=CRC32Skype(cipher);r:=make([]byte,len(cipher)+7);r[0]=0x17;r[1]=3;r[2]=1;binary.BigEndian.PutUint16(r[3:5],uint16(len(cipher)+2));copy(r[5:],cipher);r[len(r)-2]=byte(crc);r[len(r)-1]=byte(crc>>8);return r,nil}

func DirectoryRespond(req *NativeLoginRequest,db *Database)([]byte,error){
	if req.Operation!=0x4278{return nil,fmt.Errorf("not directory request")};nf,e:=Required(req.Metadata,0,0x24);if e!=nil{return nil,e};if nf.Number>1{return nil,fmt.Errorf("invalid directory fallback flag")}
	var terms []DirectoryTerm
	for _,f:=range req.Metadata{if f.ID!=0x20{continue};if f.Type!=5||len(f.Children)!=3{return nil,fmt.Errorf("invalid directory term")};p,e:=Required(f.Children,0,0x21);if e!=nil{return nil,e};c,e:=Required(f.Children,0,0x22);if e!=nil{return nil,e};t:=DirectoryTerm{Property:p.Number,Comparison:c.Number};if p.Number==17{v,e:=Required(f.Children,0,0x23);if e!=nil{return nil,e};n:=v.Number;t.Number=&n}else{v,e:=Required(f.Children,3,0x23);if e!=nil{return nil,e};if !utf8.Valid(v.Bytes){return nil,fmt.Errorf("invalid directory text")};t.Text=string(v.Bytes)};terms=append(terms,t)}
	matches,e:=db.SearchNativeDirectory(terms);if e!=nil{return nil,e};var result []Field;for _,a:=range matches{result=append(result,Field{Type:5,ID:0x64,Children:[]Field{{Type:3,ID:0x66,Bytes:[]byte(a.Login)},{Type:3,ID:0x65,Bytes:[]byte(a.DisplayName)}}})};b,e:=EncodeBlob(result);if e!=nil{return nil,e};return AccountResponse(b,req.RequestID,0x81b0)
}

func ContactDocument(contact Account)([]byte,error){return EncodeBlob([]Field{{Type:3,ID:0x10,Bytes:[]byte(contact.Login)},{Type:3,ID:0x14,Bytes:[]byte(contact.DisplayName)},fieldNumber(0x79,2)})}

func NativeContactRespond(req *NativeLoginRequest,db *Database)([]byte,error){
	if req.Operation==0x1792{f,e:=Required(req.Metadata,0,7);if e!=nil{return nil,e};if f.Number!=1{return nil,fmt.Errorf("unknown owner-local contact list")};cs,e:=db.GetContacts(req.Username);if e!=nil{return nil,e};var out []Field;for _,c:=range cs{out=append(out,Field{Type:5,ID:0x39,Children:[]Field{fieldNumber(1,0),{Type:3,ID:2,Bytes:[]byte(c.Login)}}})};b,e:=EncodeBlob(out);if e!=nil{return nil,e};return AccountResponse(b,req.RequestID,0x1450)}
	inst,e:=Required(req.Metadata,1,0x3a);if e!=nil{return nil,e};if len(inst.Bytes)!=8{return nil,fmt.Errorf("invalid native document client identifier")}
	var body []Field;var rev uint32
	switch req.Operation{
	case 0x1789:
		n,e:=Required(req.Metadata,3,0x34);if e!=nil{return nil,e};v,e:=Required(req.Metadata,4,0x33);if e!=nil{return nil,e};c,e:=Required(req.Metadata,0,0x32);if e!=nil{return nil,e};if !utf8.Valid(n.Bytes){return nil,fmt.Errorf("invalid document name")};rev,e=db.PutNativeDocument(req.Username,string(n.Bytes),v.Bytes,c.Number);if e!=nil{return nil,e}
	case 0x178a:
		n,e:=Required(req.Metadata,3,0x34);if e!=nil{return nil,e};if !utf8.Valid(n.Bytes){return nil,fmt.Errorf("invalid document name")};rev,e=db.RemoveNativeDocument(req.Username,string(n.Bytes));if e!=nil{return nil,e}
	case 0x178b,0x178c,0x1788:
		if req.Operation==0x178b||req.Operation==0x178c{if e:=db.EnsureNativeContactDocuments(req.Username);e!=nil{return nil,e}}
		s,e:=db.GetNativeDocuments(req.Username);if e!=nil{return nil,e};rev=s.Revision
		if req.Operation==0x178b||req.Operation==0x178c{checks:=make([]byte,len(s.Documents)*4);for i,d:=range s.Documents{binary.BigEndian.PutUint32(checks[i*4:],d.Checksum)};body=append(body,Field{Type:4,ID:0x35,Bytes:checks})}else{c,e:=Required(req.Metadata,0,0x32);if e!=nil{return nil,e};var found *NativeDocument;for i:=range s.Documents{if s.Documents[i].Checksum==c.Number{found=&s.Documents[i];break}};if found==nil{return nil,fmt.Errorf("native document absent")};body=append(body,Field{Type:5,ID:0x37,Children:[]Field{{Type:3,ID:0x34,Bytes:[]byte(found.Name)},{Type:4,ID:0x33,Bytes:found.Body}}})}
	default:return nil,fmt.Errorf("unsupported native document operation")
	}
	body=append([]Field{fieldNumber(0x36,rev)},body...);enc,e:=EncodeBlob(body);if e!=nil{return nil,e};return AccountResponse(enc,req.RequestID,0x1450)
}

func validUsername(s string)bool{if s==""||len(s)>128{return false};for _,r:=range s{if unicode.IsControl(r){return false}};return true}
