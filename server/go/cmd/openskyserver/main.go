package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/IlyaBOT/Open-SkyServer/server/go/internal/keys"
	"github.com/IlyaBOT/Open-SkyServer/server/go/internal/server"
)

func main(){
	cfg,err:=server.ParseConfig(os.Args[1:]);if err!=nil{log.Fatal(err)}
	server.SetBlobWorker(cfg.BlobWorker)
	var ks *keys.Set
	if st,e:=os.Stat(cfg.KeysDir);e==nil&&st.IsDir(){ks,err=keys.Load(cfg.KeysDir);if err!=nil{log.Fatalf("keys: %v",err)};log.Printf("community login RSA-1536/e65537 modulus SHA256: %s",ks.LoginFingerprint);log.Printf("community credentials RSA-2048/e65537 modulus SHA256: %s",ks.CredentialsFingerprint)}
	if cfg.Command==server.CheckKeys{if ks==nil{log.Fatal("no key set found; generate keys/ or pass --keys-dir")};log.Print("RSA private/public pair tests passed.");return}
	if err:=server.EnsureDatabaseDirectory(cfg.DBPath);err!=nil{log.Fatal(err)}
	db:=server.NewDatabase(cfg.DBPath,cfg.SQLite);if err=db.EnsureSchema();err!=nil{log.Fatal(err)}
	switch cfg.Command{
	case server.InitDB:fmt.Printf("database initialized: %s\n",cfg.DBPath);return
	case server.AddAccount:err=db.AddAccount(cfg.CommandArgs[0],cfg.CommandArgs[1],cfg.CommandArgs[2])
	case server.RemoveAccount:err=db.RemoveAccount(cfg.CommandArgs[0])
	case server.AddContact:err=db.AddContact(cfg.CommandArgs[0],cfg.CommandArgs[1])
	case server.SetEmail:err=db.SetAccountEmail(cfg.CommandArgs[0],cfg.CommandArgs[1])
	}
	if cfg.Command!=server.Serve{if err!=nil{log.Fatal(err)};log.Print("database command completed");return}
	var access *server.AccessPolicy
	if cfg.Closed{access,err=server.LoadAccess(cfg.Allowlist)}else{access=server.OpenAccess()};if err!=nil{log.Fatal(err)}
	if ks==nil&&cfg.RealSkype{log.Fatal("--real-skype-probe requires community keys")}
	ctx,cancel:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer cancel()
	api:=&server.APIServer{DB:db,Access:access,Host:cfg.APIHost,Port:cfg.APIPort};apiSrv,err:=api.Run();if err!=nil{log.Fatal(err)};defer apiSrv.Close()
	auth:=&server.AuthServer{DB:db,Keys:ks,Access:access,Host:cfg.Host,Port:cfg.Port,Once:cfg.Once,RealSkype:cfg.RealSkype}
	if cfg.RealSkype{
		tcpPorts:=server.DefaultTCPPorts(cfg.Port,cfg.APIPort);udpPorts:=server.DefaultUDPPorts(cfg.Port)
		if cfg.IncludeHostCache{extra,e:=server.HostCachePorts(cfg.SharedXML);if e!=nil{log.Fatal(e)};tcpPorts=append(tcpPorts,extra...);udpPorts=append(udpPorts,extra...)}
		tcp:=&server.TCPProbeServer{Host:cfg.Host,Ports:tcpPorts,AdvertiseIP:cfg.AdvertiseIP,Access:access,Auth:auth,Keys:ks};tcp.Run(ctx)
		udp:=&server.UDPServer{Host:cfg.Host,Ports:udpPorts,AdvertiseIP:cfg.AdvertiseIP,Access:access};udp.Run(ctx)
	}
	log.Printf("OpenSkyServer Go mode=%s auth=%s api=%s advertise=%v db=%s",cfg.Mode,net.JoinHostPort(cfg.Host,fmt.Sprint(cfg.Port)),net.JoinHostPort(cfg.APIHost,fmt.Sprint(cfg.APIPort)),cfg.AdvertiseIP,filepath.Clean(cfg.DBPath))
	go func(){<-ctx.Done();_ = apiSrv.Shutdown(context.Background())}()
	if err=auth.Run(ctx);err!=nil&&err!=http.ErrServerClosed{log.Fatal(err)}
}
