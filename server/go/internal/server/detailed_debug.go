package server

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
)

var detailedDebugEnabled atomic.Bool

// SetDetailedDebug enables opt-in verbose protocol diagnostics.
// It is intentionally process-global because the server has one protocol instance.
func SetDetailedDebug(enabled bool) {
	detailedDebugEnabled.Store(enabled)
}

type signedRecordEndpoint struct {
	Path    string
	Address string
}

func signedRecordEndpoints(fields []Field) []signedRecordEndpoint {
	var out []signedRecordEndpoint
	var walk func([]Field, string)
	walk = func(list []Field, prefix string) {
		for _, f := range list {
			path := fmt.Sprintf("%d:%x", f.Type, f.ID)
			if prefix != "" {
				path = prefix + "/" + path
			}
			if f.Type == 2 && len(f.Bytes) == 6 {
				ip := net.IPv4(f.Bytes[0], f.Bytes[1], f.Bytes[2], f.Bytes[3]).String()
				port := binary.BigEndian.Uint16(f.Bytes[4:])
				out = append(out, signedRecordEndpoint{
					Path:    path,
					Address: fmt.Sprintf("%s:%d", ip, port),
				})
			}
			if len(f.Children) != 0 {
				walk(f.Children, path)
			}
		}
	}
	walk(fields, "")
	return out
}

func describeSignedRecordFields(fields []Field) string {
	var b strings.Builder
	seen := 0
	var walk func([]Field, int)
	walk = func(list []Field, depth int) {
		b.WriteByte('[')
		for i, f := range list {
			if seen >= 96 {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString("...")
				break
			}
			if i > 0 {
				b.WriteByte(',')
			}
			seen++
			fmt.Fprintf(&b, "%d:%x", f.Type, f.ID)
			switch f.Type {
			case 0:
				fmt.Fprintf(&b, "=%d", f.Number)
			case 2:
				if len(f.Bytes) == 6 {
					fmt.Fprintf(
						&b,
						"=%s:%d",
						net.IPv4(f.Bytes[0], f.Bytes[1], f.Bytes[2], f.Bytes[3]).String(),
						binary.BigEndian.Uint16(f.Bytes[4:]),
					)
				} else {
					fmt.Fprintf(&b, "[%d]", len(f.Bytes))
				}
			case 1, 3, 4, 6:
				fmt.Fprintf(&b, "[%d]", len(f.Bytes))
			case 5:
				if depth >= 7 {
					fmt.Fprintf(&b, "{%d}", len(f.Children))
				} else {
					walk(f.Children, depth+1)
				}
			}
		}
		b.WriteByte(']')
	}
	walk(fields, 0)
	return b.String()
}

func logDetailedSignedRecord(record *SignedRecord, wireLength int) {
	if !detailedDebugEnabled.Load() || record == nil {
		return
	}
	log.Printf(
		"detailed signed record user=%q bytes=%d fields=%s",
		record.Username,
		wireLength,
		describeSignedRecordFields(record.Fields),
	)
	endpoints := signedRecordEndpoints(record.Fields)
	if len(endpoints) == 0 {
		log.Printf("detailed signed record endpoints user=%q none", record.Username)
		return
	}
	for _, endpoint := range endpoints {
		log.Printf(
			"detailed signed record endpoint user=%q path=%q address=%s",
			record.Username,
			endpoint.Path,
			endpoint.Address,
		)
	}
}
