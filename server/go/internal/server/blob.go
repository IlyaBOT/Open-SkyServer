package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

type Field struct {
	Type     byte
	ID       uint32
	Number   uint32
	Bytes    []byte
	Children []Field
}

var blobWorkerPath = os.Getenv("SKYSERVER_BLOB_WORKER")

func SetBlobWorker(path string) { blobWorkerPath = path }

func writeVarint(w io.Writer, value uint32) error {
	var b [1]byte
	for value >= 128 {
		b[0] = byte(value) | 0x80
		if _, err := w.Write(b[:]); err != nil { return err }
		value >>= 7
	}
	b[0] = byte(value)
	_, err := w.Write(b[:])
	return err
}

func EncodeBlob(fields []Field) ([]byte, error) {
	var out bytes.Buffer
	budget := 4096
	if err := writeList(&out, fields, 0, &budget); err != nil { return nil, err }
	return out.Bytes(), nil
}

func writeList(out *bytes.Buffer, fields []Field, depth int, budget *int) error {
	if depth >= 8 || len(fields) > *budget { return fmt.Errorf("invalid output blob list") }
	*budget -= len(fields)
	out.WriteByte(0x41)
	if err := writeVarint(out, uint32(len(fields))); err != nil { return err }
	for _, f := range fields {
		out.WriteByte(f.Type)
		if err := writeVarint(out, f.ID); err != nil { return err }
		switch f.Type {
		case 0:
			if err := writeVarint(out, f.Number); err != nil { return err }
		case 1:
			if len(f.Bytes) != 8 { return fmt.Errorf("invalid type-1 blob") }
			out.Write(f.Bytes)
		case 2:
			if len(f.Bytes) != 6 { return fmt.Errorf("invalid type-2 blob") }
			out.Write(f.Bytes)
		case 3:
			if bytes.IndexByte(f.Bytes, 0) >= 0 { return fmt.Errorf("NUL in blob string") }
			out.Write(f.Bytes); out.WriteByte(0)
		case 4:
			if err := writeVarint(out, uint32(len(f.Bytes))); err != nil { return err }
			out.Write(f.Bytes)
		case 5:
			if err := writeList(out, f.Children, depth+1, budget); err != nil { return err }
		case 6:
			if len(f.Bytes)%4 != 0 || len(f.Bytes) > 16384 { return fmt.Errorf("invalid blob words") }
			if err := writeVarint(out, uint32(len(f.Bytes)/4)); err != nil { return err }
			for i:=0;i<len(f.Bytes);i+=4 {
				if err := writeVarint(out, binary.LittleEndian.Uint32(f.Bytes[i:i+4])); err != nil { return err }
			}
		default:
			return fmt.Errorf("unknown blob type %d", f.Type)
		}
		if out.Len() > 16384 { return fmt.Errorf("output blob size limit") }
	}
	return nil
}

func DecodeBlob(input []byte) ([]Field, int, error) {
	if len(input)==0 || len(input)>16384 { return nil,0,fmt.Errorf("invalid 41/42 input size") }
	data := input
	consumed := 0
	if input[0] == 0x42 {
		norm, used, err := normalize42(input)
		if err != nil { return nil,0,err }
		data, consumed = norm, used
	} else if input[0] != 0x41 {
		return nil,0,fmt.Errorf("expected a 41/42 list")
	}
	at, budget := 0, 4096
	fields, err := readList(data, &at, 0, &budget)
	if err != nil { return nil,0,err }
	if input[0] == 0x42 {
		if at != len(data) { return nil,0,fmt.Errorf("trailing normalized blob bytes") }
		return fields, consumed, nil
	}
	return fields, at, nil
}

func readList(data []byte, at *int, depth int, budget *int) ([]Field,error) {
	if depth>=8 || *at>=len(data) || data[*at]!=0x41 { return nil,fmt.Errorf("invalid nested 41 list") }
	*at++
	count,err:=readVarint(data,at); if err!=nil{return nil,err}
	if int(count)>*budget { return nil,fmt.Errorf("too many blob fields") }
	*budget-=int(count)
	out:=make([]Field,0,count)
	for i:=uint32(0);i<count;i++ {
		if *at>=len(data){return nil,fmt.Errorf("truncated blob")}
		f:=Field{Type:data[*at]}; *at++
		f.ID,err=readVarint(data,at); if err!=nil{return nil,err}
		switch f.Type {
		case 0:
			f.Number,err=readVarint(data,at)
		case 1:
			f.Bytes,err=take(data,at,8)
		case 2:
			f.Bytes,err=take(data,at,6)
		case 3:
			start:=*at
			for *at<len(data)&&data[*at]!=0 { *at++ }
			if *at>=len(data){return nil,fmt.Errorf("unterminated blob string")}
			f.Bytes=append([]byte(nil),data[start:*at]...); *at++
		case 4:
			var n uint32; n,err=readVarint(data,at); if err==nil { f.Bytes,err=take(data,at,int(n)) }
		case 5:
			f.Children,err=readList(data,at,depth+1,budget)
		case 6:
			var n uint32; n,err=readVarint(data,at)
			if err==nil {
				if n>4096{return nil,fmt.Errorf("too many blob words")}
				f.Bytes=make([]byte,int(n)*4)
				for j:=uint32(0);j<n;j++ { var v uint32; v,err=readVarint(data,at); if err!=nil{break}; binary.LittleEndian.PutUint32(f.Bytes[int(j)*4:],v) }
			}
		default:
			return nil,fmt.Errorf("unknown blob type")
		}
		if err!=nil{return nil,err}
		out=append(out,f)
	}
	return out,nil
}

func readVarint(data []byte, at *int)(uint32,error){
	var v uint32
	for shift:=uint(0);shift<=28;shift+=7 {
		if *at>=len(data){return 0,fmt.Errorf("truncated blob varint")}
		b:=data[*at]; *at++
		if shift==28 && b&0xf0!=0{return 0,fmt.Errorf("blob varint overflow")}
		v|=uint32(b&0x7f)<<shift
		if b&0x80==0{return v,nil}
	}
	return 0,fmt.Errorf("invalid blob varint")
}

func take(data []byte, at *int, n int)([]byte,error){
	if n<0 || *at>len(data)-n{return nil,fmt.Errorf("blob length exceeds remaining input")}
	b:=append([]byte(nil),data[*at:*at+n]...); *at+=n; return b,nil
}

func Required(fields []Field, typ byte, id uint32)(Field,error){
	var found *Field
	for i:=range fields {
		if fields[i].ID!=id{continue}
		if found!=nil || fields[i].Type!=typ{return Field{},fmt.Errorf("duplicate or mistyped required field %d/%x",typ,id)}
		found=&fields[i]
	}
	if found==nil{return Field{},fmt.Errorf("required field %d/%x is absent",typ,id)}
	return *found,nil
}

type cappedWriter struct { b bytes.Buffer; max int }
func (w *cappedWriter) Write(p []byte)(int,error){
	if w.b.Len()+len(p)>w.max{return 0,fmt.Errorf("blob worker output limit")}
	return w.b.Write(p)
}

func normalize42(input []byte)([]byte,int,error){
	if blobWorkerPath=="" { return nil,0,fmt.Errorf("compressed 42 blob requires --blob-worker") }
	ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second); defer cancel()
	cmd:=exec.CommandContext(ctx,blobWorkerPath)
	cmd.Stdin=bytes.NewReader(input)
	var out cappedWriter; out.max=65540
	var stderr bytes.Buffer
	cmd.Stdout=&out; cmd.Stderr=&stderr
	if err:=cmd.Run();err!=nil {
		if ctx.Err()!=nil{return nil,0,fmt.Errorf("blob worker timeout")}
		return nil,0,fmt.Errorf("blob worker rejected packet: %v %s",err,stderr.String())
	}
	raw:=out.b.Bytes()
	if len(raw)<6{return nil,0,fmt.Errorf("short blob worker output")}
	used:=int(binary.LittleEndian.Uint32(raw[:4]))
	if used<=0 || used>len(input){return nil,0,fmt.Errorf("invalid blob consumption count")}
	norm:=append([]byte(nil),raw[4:]...)
	if len(norm)==0 || norm[0]!=0x41{return nil,0,fmt.Errorf("invalid normalized blob")}
	return norm,used,nil
}
