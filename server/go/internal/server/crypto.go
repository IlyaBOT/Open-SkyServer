package server

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math/big"
)

var dhModulus = func()*big.Int {
	n,_:=new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B13B202FFFFFFFFFFFFFFFF",16)
	return n
}()

type DHSession struct {
	ServerHello []byte
	ServerHash []byte
	ExpectedClientHash []byte
	SharedSecret []byte
}

func NewDHSession(client []byte)(*DHSession,error){
	if len(client)<48{return nil,fmt.Errorf("DH384 packet is shorter than public key")}
	cp:=new(big.Int).SetBytes(client[:48])
	if cp.Cmp(big.NewInt(1))<=0 || cp.Cmp(dhModulus)>=0{return nil,fmt.Errorf("DH384 public key outside valid range")}
	var secret *big.Int
	for {
		b:=make([]byte,48); if _,err:=rand.Read(b);err!=nil{return nil,err}; b[0]&=0x7f
		secret=new(big.Int).SetBytes(b)
		if secret.Cmp(big.NewInt(1))>0 && secret.Cmp(dhModulus)<0{break}
	}
	pub:=new(big.Int).Exp(big.NewInt(2),secret,dhModulus)
	shared:=new(big.Int).Exp(cp,secret,dhModulus)
	pb:=make([]byte,48); pub.FillBytes(pb)
	sb:=make([]byte,48); shared.FillBytes(sb)
	hello:=make([]byte,51); copy(hello,pb); if _,err:=rand.Read(hello[48:]);err!=nil{return nil,err}
	hash:=func(prefix byte)[]byte{ x:=append([]byte{prefix},sb...); h:=md5.Sum(x); return append([]byte(nil),h[:8]...) }
	return &DHSession{ServerHello:hello,ExpectedClientHash:hash('O'),ServerHash:hash('I'),SharedSecret:sb},nil
}

func (d *DHSession) VerifyClientHash(b []byte)bool{
	return len(b)>=8 && subtle.ConstantTimeCompare(b[:8],d.ExpectedClientHash)==1
}

func newRC4(key []byte)(*rc4.Cipher,error){ return rc4.NewCipher(key) }
func incrementFirst(b []byte)[]byte{ out:=append([]byte(nil),b...); if len(out)>0{out[0]++}; return out }

func DeriveLoginAESKey(material []byte)([]byte,error){
	if len(material)!=192{return nil,fmt.Errorf("expected 192 bytes of RSA session material")}
	input:=make([]byte,196); copy(input[4:],material)
	a:=sha1.Sum(input)
	key:=make([]byte,32); copy(key,a[:])
	input[3]=1
	b:=sha1.Sum(input); copy(key[20:],b[:12])
	return key,nil
}

func LoginAESCTR(key,data []byte,iv uint32)([]byte,error){
	if len(key)!=32{return nil,fmt.Errorf("AES-256 key required")}
	block,err:=aes.NewCipher(key); if err!=nil{return nil,err}
	out:=make([]byte,len(data)); counter:=make([]byte,16); binary.BigEndian.PutUint32(counter[0:4],iv); binary.BigEndian.PutUint32(counter[4:8],iv)
	pad:=make([]byte,16)
	for off:=0;off<len(data);off+=16 {
		binary.BigEndian.PutUint32(counter[12:16],uint32(off/16)); block.Encrypt(pad,counter)
		for i:=0;i<16 && off+i<len(data);i++{out[off+i]=data[off+i]^pad[i]}
	}
	return out,nil
}

func CRC32Skype(data []byte)uint32{
	z:=uint32(0xffffffff)
	for _,b:=range data { z^=uint32(b); for j:=0;j<8;j++{if z&1!=0{z=(z>>1)^0xedb88320}else{z>>=1}} }
	return z
}
