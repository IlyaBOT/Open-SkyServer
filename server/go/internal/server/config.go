package server

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Command int
const(Serve Command=iota; InitDB; AddAccount; RemoveAccount; AddContact; SetEmail; CheckKeys)
type Config struct{
	Mode string
	Host string
	Port int
	APIHost string
	APIPort int
	AdvertiseIP net.IP
	DBPath string
	SQLite string
	KeysDir string
	BlobWorker string
	RealSkype bool
	DetailedDebug bool
	Once bool
	Closed bool
	Allowlist string
	IncludeHostCache bool
	SharedXML string
	Command Command
	CommandArgs []string
}

func defaultPaths()(string,string,string){
	exe,_:=os.Executable();dir:=filepath.Dir(exe);db:=filepath.Join(dir,"skyserver.db");keys:=os.Getenv("SKYSERVER_KEYS_DIR");if keys==""{if st,e:=os.Stat(filepath.Join(dir,"keys"));e==nil&&st.IsDir(){keys=filepath.Join(dir,"keys")}else{keys=filepath.Join("..","csharp","keys")}}
	worker:=filepath.Join(dir,"skype_blob_worker");return db,keys,worker
}
func ParseConfig(args []string)(Config,error){
	db,keys,worker:=defaultPaths();sql:=os.Getenv("SKYSERVER_SQLITE");if sql==""{sql="sqlite3"}
	c:=Config{Mode:"local",Host:"127.0.0.1",Port:33033,APIHost:"127.0.0.1",APIPort:33034,DBPath:db,SQLite:sql,KeysDir:keys,BlobWorker:worker,Command:Serve}
	hostSet:=false;apiSet:=false
	next:=func(i *int)(string,error){if *i+1>=len(args){return "",fmt.Errorf("missing value after %s",args[*i])};*i++;return args[*i],nil}
	for i:=0;i<len(args);i++{a:=args[i];switch a{
	case "--mode":v,e:=next(&i);if e!=nil{return c,e};c.Mode=v
	case "--host":v,e:=next(&i);if e!=nil{return c,e};ip:=net.ParseIP(v);if ip==nil||ip.To4()==nil{return c,fmt.Errorf("--host must be an IPv4 address")};c.Host=ip.To4().String();hostSet=true
	case "--port":v,e:=next(&i);if e!=nil{return c,e};n,e:=strconv.Atoi(v);if e!=nil{return c,e};c.Port=n
	case "--api-host":v,e:=next(&i);if e!=nil{return c,e};ip:=net.ParseIP(v);if ip==nil||ip.To4()==nil{return c,fmt.Errorf("--api-host must be an IPv4 address")};c.APIHost=ip.To4().String();apiSet=true
	case "--api-port":v,e:=next(&i);if e!=nil{return c,e};n,e:=strconv.Atoi(v);if e!=nil{return c,e};c.APIPort=n
	case "--advertise-ip":v,e:=next(&i);if e!=nil{return c,e};ip:=net.ParseIP(v);if ip==nil||ip.To4()==nil{return c,fmt.Errorf("--advertise-ip must be an IPv4 address")};c.AdvertiseIP=ip.To4()
	case "--db":v,e:=next(&i);if e!=nil{return c,e};c.DBPath=v
	case "--sqlite":v,e:=next(&i);if e!=nil{return c,e};c.SQLite=v
	case "--keys-dir":v,e:=next(&i);if e!=nil{return c,e};c.KeysDir=v
	case "--blob-worker":v,e:=next(&i);if e!=nil{return c,e};c.BlobWorker=v
	case "--real-skype-probe":c.RealSkype=true
	case "--detailed-debug":c.DetailedDebug=true
	case "--once":c.Once=true
	case "--closed":c.Closed=true
	case "--allowlist":v,e:=next(&i);if e!=nil{return c,e};c.Allowlist=v
	case "--include-hostcache-probe":c.IncludeHostCache=true
	case "--skype-shared-xml":v,e:=next(&i);if e!=nil{return c,e};c.SharedXML=v
	case "--check-keys":c.Command=CheckKeys
	case "--init-db":c.Command=InitDB
	case "--add-account":if i+3>=len(args){return c,fmt.Errorf("--add-account requires login display password")};c.Command=AddAccount;c.CommandArgs=[]string{args[i+1],args[i+2],args[i+3]};i+=3
	case "--remove-account":v,e:=next(&i);if e!=nil{return c,e};c.Command=RemoveAccount;c.CommandArgs=[]string{v}
	case "--add-contact":if i+2>=len(args){return c,fmt.Errorf("--add-contact requires owner contact")};c.Command=AddContact;c.CommandArgs=[]string{args[i+1],args[i+2]};i+=2
	case "--set-email":if i+2>=len(args){return c,fmt.Errorf("--set-email requires login email")};c.Command=SetEmail;c.CommandArgs=[]string{args[i+1],args[i+2]};i+=2
	default:return c,fmt.Errorf("unknown argument %s",a)
	}}
	if c.Mode!="local"&&c.Mode!="global"{return c,fmt.Errorf("--mode must be local or global")}
	if c.AdvertiseIP!=nil{v:=c.AdvertiseIP.To4();if v==nil||v[0]==0||v[0]>=224{return c,fmt.Errorf("--advertise-ip must be unicast IPv4")}}
	if c.Mode=="global"{if !hostSet{c.Host="0.0.0.0"};if !apiSet{c.APIHost="127.0.0.1"};if c.AdvertiseIP==nil||c.AdvertiseIP.IsLoopback(){return c,fmt.Errorf("global mode requires --advertise-ip with a concrete non-loopback IPv4 address")};api:=net.ParseIP(c.APIHost);if api==nil||!api.IsLoopback(){return c,fmt.Errorf("global mode requires loopback --api-host")}}
	if c.Port<1||c.Port>65535||c.APIPort<1||c.APIPort>65535||c.Port==c.APIPort{return c,fmt.Errorf("auth/API ports must be distinct and between 1 and 65535")}
	if c.Closed&&c.Allowlist==""{return c,fmt.Errorf("--closed requires --allowlist")}
	return c,nil
}

type sharedConfig struct{HostCache string `xml:"Lib>Connection>HostCache"`}
func HostCachePorts(path string)([]int,error){
	if path==""{return nil,nil};data,e:=os.ReadFile(path);if os.IsNotExist(e){return nil,nil};if e!=nil{return nil,e};var c sharedConfig;if e=xml.Unmarshal(data,&c);e!=nil{return nil,e};h:=strings.TrimSpace(c.HostCache);if h==""{return nil,nil};b,e:=hex.DecodeString(h);if e!=nil{return nil,e};var p []int
	for i:=0;i+9<len(b);i++{if b[i]==0x41&&b[i+1]==5&&b[i+2]==2&&b[i+3]==0{port:=int(b[i+8])<<8|int(b[i+9]);if port>0{p=append(p,port)}}};return uniquePorts(p),nil
}
