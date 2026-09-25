//go:build !linux

package server

import "net"

func enableUDPDestination(c *net.UDPConn) error { return nil }

func readUDPDatagram(c *net.UDPConn, buf []byte) (int, *net.UDPAddr, net.IP, error) {
	n, remote, err := c.ReadFromUDP(buf)
	if err != nil { return 0, nil, nil, err }
	var destination net.IP
	if local, ok := c.LocalAddr().(*net.UDPAddr); ok && local.IP != nil && !local.IP.IsUnspecified() {
		destination = append(net.IP(nil), local.IP.To4()...)
	}
	return n, remote, destination, nil
}
