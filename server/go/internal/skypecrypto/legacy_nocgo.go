//go:build !cgo

package skypecrypto

import "fmt"

type Session struct{}
func NewSession()(*Session,error){return nil,fmt.Errorf("Skype native RC4 requires CGO_ENABLED=1")}
func (s *Session) Close(){}
func (s *Session) MakeServerHandshake([]byte)([]byte,error){return nil,fmt.Errorf("Skype native RC4 requires cgo")}
func (s *Session) DecryptClientHandshake([]byte,[]byte)([]byte,error){return nil,fmt.Errorf("Skype native RC4 requires cgo")}
func (s *Session) Decrypt([]byte)([]byte,error){return nil,fmt.Errorf("Skype native RC4 requires cgo")}
func (s *Session) Encrypt([]byte)([]byte,error){return nil,fmt.Errorf("Skype native RC4 requires cgo")}
func UdpCrypt(uint32,[]byte)([]byte,error){return nil,fmt.Errorf("Skype native RC4 requires cgo")}
