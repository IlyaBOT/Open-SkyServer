package server

import (
	"encoding/binary"
	"encoding/hex"
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
	Kind    string
	Address string
}

type signedRecordVCard struct {
	NodeID     string
	Flag       byte
	Internal   string
	External   string
	Additional string
}

func endpointFromBytes(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	ip := net.IPv4(b[0], b[1], b[2], b[3]).String()
	port := binary.BigEndian.Uint16(b[4:])
	return fmt.Sprintf("%s:%d", ip, port)
}

func decodeSignedRecordVCard(b []byte) (signedRecordVCard, bool) {
	if len(b) != 27 {
		return signedRecordVCard{}, false
	}
	return signedRecordVCard{
		NodeID:     hex.EncodeToString(b[:8]),
		Flag:       b[8],
		Internal:   endpointFromBytes(b[9:15]),
		External:   endpointFromBytes(b[15:21]),
		Additional: endpointFromBytes(b[21:27]),
	}, true
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
				out = append(out, signedRecordEndpoint{
					Path:    path,
					Kind:    "type2",
					Address: endpointFromBytes(f.Bytes),
				})
			}
			if f.Type == 4 && f.ID == 3 {
				if card, ok := decodeSignedRecordVCard(f.Bytes); ok {
					out = append(out,
						signedRecordEndpoint{Path: path, Kind: "vcard-internal", Address: card.Internal},
						signedRecordEndpoint{Path: path, Kind: "vcard-external", Address: card.External},
						signedRecordEndpoint{Path: path, Kind: "vcard-additional", Address: card.Additional},
					)
				}
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
					fmt.Fprintf(&b, "=%s", endpointFromBytes(f.Bytes))
				} else {
					fmt.Fprintf(&b, "[%d]", len(f.Bytes))
				}
			case 4:
				if f.ID == 3 {
					if card, ok := decodeSignedRecordVCard(f.Bytes); ok {
						fmt.Fprintf(
							&b,
							"[vcard node=%s flag=0x%02x internal=%s external=%s additional=%s]",
							card.NodeID,
							card.Flag,
							card.Internal,
							card.External,
							card.Additional,
						)
						break
					}
				}
				fmt.Fprintf(&b, "[%d]", len(f.Bytes))
			case 1, 3, 6:
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
			"detailed signed record endpoint user=%q path=%q kind=%q address=%s",
			record.Username,
			endpoint.Path,
			endpoint.Kind,
			endpoint.Address,
		)
	}
}
