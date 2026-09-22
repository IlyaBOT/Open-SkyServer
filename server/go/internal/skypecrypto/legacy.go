//go:build cgo

package skypecrypto

/*
#include <stdint.h>
#include <stdlib.h>
void *os_session_create(void);
void os_session_free(void *);
int os_session_make(void *, const unsigned char *, int, uint32_t, uint16_t, int, unsigned char *, int);
int os_session_client_handshake(void *, const unsigned char *, int, const unsigned char *, int, unsigned char *, int);
int os_session_decrypt(void *, const unsigned char *, int, unsigned char *, int);
int os_session_encrypt(void *, const unsigned char *, int, unsigned char *, int);
int os_udp_crypt(uint32_t, const unsigned char *, int, unsigned char *, int);
*/
import "C"

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"runtime"
	"unsafe"
)

type Session struct{ p unsafe.Pointer }

func NewSession()(*Session,error){
	p:=C.os_session_create();if p==nil{return nil,fmt.Errorf("native RC4 session allocation failed")}
	s:=&Session{p:p};runtime.SetFinalizer(s,func(x *Session){x.Close()});return s,nil
}
func (s *Session) Close(){if s!=nil&&s.p!=nil{C.os_session_free(s.p);s.p=nil;runtime.SetFinalizer(s,nil)}}
func random32()(uint32,error){var b [4]byte;if _,e:=rand.Read(b[:]);e!=nil{return 0,e};return binary.LittleEndian.Uint32(b[:]),nil}

func cptr(b []byte)*C.uchar{if len(b)==0{return nil};return (*C.uchar)(unsafe.Pointer(&b[0]))}

func (s *Session) MakeServerHandshake(secret []byte)([]byte,error){
	if len(secret)<48{return nil,fmt.Errorf("short DH secret")};iv,e:=random32();if e!=nil{return nil,e};q,e:=random32();if e!=nil{return nil,e};g,e:=random32();if e!=nil{return nil,e}
	out:=make([]byte,256);n:=int(C.os_session_make(s.p,cptr(secret),C.int(len(secret)),C.uint32_t(iv),C.uint16_t(q&0xffff),C.int(20+g%16),cptr(out),C.int(len(out))))
	if n<=0{return nil,fmt.Errorf("native RC4 handshake returned %d",n)};return out[:n],nil
}
func (s *Session) DecryptClientHandshake(secret,in []byte)([]byte,error){
	out:=make([]byte,len(in));n:=int(C.os_session_client_handshake(s.p,cptr(secret),C.int(len(secret)),cptr(in),C.int(len(in)),cptr(out),C.int(len(out))));if n<=0{return nil,fmt.Errorf("native RC4 client handshake returned %d",n)};return out[:n],nil
}
func (s *Session) Decrypt(in []byte)([]byte,error){out:=make([]byte,len(in));if len(in)==0{return out,nil};n:=int(C.os_session_decrypt(s.p,cptr(in),C.int(len(in)),cptr(out),C.int(len(out))));if n<0{return nil,fmt.Errorf("native RC4 decrypt returned %d",n)};return out[:n],nil}
func (s *Session) Encrypt(in []byte)([]byte,error){out:=make([]byte,len(in));if len(in)==0{return out,nil};n:=int(C.os_session_encrypt(s.p,cptr(in),C.int(len(in)),cptr(out),C.int(len(out))));if n<0{return nil,fmt.Errorf("native RC4 encrypt returned %d",n)};return out[:n],nil}
func UdpCrypt(iv uint32,in []byte)([]byte,error){out:=make([]byte,len(in));if len(in)==0{return out,nil};n:=int(C.os_udp_crypt(C.uint32_t(iv),cptr(in),C.int(len(in)),cptr(out),C.int(len(out))));if n<0{return nil,fmt.Errorf("native UDP RC4 returned %d",n)};return out[:n],nil}
