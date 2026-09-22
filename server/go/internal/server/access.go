package server

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

type AccessPolicy struct {
	open bool
	nets []*net.IPNet
}

func OpenAccess() *AccessPolicy { return &AccessPolicy{open: true} }

func LoadAccess(path string) (*AccessPolicy, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()
	p := &AccessPolicy{}
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(strings.SplitN(sc.Text(), "#", 2)[0])
		if s == "" { continue }
		if !strings.Contains(s, "/") {
			ip := net.ParseIP(s)
			if ip == nil || ip.To4() == nil { return nil, fmt.Errorf("%s:%d: expected IPv4 address or CIDR", path, line) }
			s = ip.To4().String()+"/32"
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil || n.IP.To4() == nil { return nil, fmt.Errorf("%s:%d: invalid IPv4 CIDR", path, line) }
		p.nets = append(p.nets, n)
	}
	if err := sc.Err(); err != nil { return nil, err }
	return p, nil
}

func (p *AccessPolicy) Allows(ip net.IP) bool {
	if p == nil || p.open { return true }
	v4 := ip.To4()
	if v4 == nil { return false }
	for _, n := range p.nets { if n.Contains(v4) { return true } }
	return false
}
