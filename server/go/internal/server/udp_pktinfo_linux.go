//go:build linux

package server

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

func enableUDPDestination(c *net.UDPConn) error {
	raw, err := c.SyscallConn()
	if err != nil { return err }
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
	}); err != nil { return err }
	return sockErr
}

func readUDPDatagram(c *net.UDPConn, buf []byte) (int, *net.UDPAddr, net.IP, error) {
	oob := make([]byte, 128)
	n, oobn, _, remote, err := c.ReadMsgUDP(buf, oob)
	if err != nil { return 0, nil, nil, err }
	var destination net.IP
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil { return 0, nil, nil, err }
	for _, msg := range msgs {
		if msg.Header.Level != syscall.IPPROTO_IP || msg.Header.Type != syscall.IP_PKTINFO { continue }
		// Linux struct in_pktinfo:
		//   int ipi_ifindex; struct in_addr ipi_spec_dst; struct in_addr ipi_addr;
		if len(msg.Data) < 12 { return 0, nil, nil, fmt.Errorf("short IP_PKTINFO control message") }
		destination = net.IPv4(msg.Data[8], msg.Data[9], msg.Data[10], msg.Data[11]).To4()
		_ = binary.NativeEndian.Uint32(msg.Data[:4]) // validate/native-size access; ifindex is informational.
		break
	}
	if destination == nil {
		if local, ok := c.LocalAddr().(*net.UDPAddr); ok && local.IP != nil && !local.IP.IsUnspecified() {
			destination = append(net.IP(nil), local.IP.To4()...)
		}
	}
	return n, remote, destination, nil
}
