package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/IlyaBOT/Open-SkyServer/server/go/internal/keys"
)

func serveTCP(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil { return nil, err }
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil { return }
			// Protocol handlers are being ported from server/csharp. Until then,
			// never pretend an unknown request authenticated successfully.
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_ = c.Close()
		}
	}()
	return ln, nil
}

func main() {
	host := flag.String("host", "127.0.0.1", "auth listener address")
	port := flag.Int("port", 33033, "auth listener port")
	apiHost := flag.String("api-host", "127.0.0.1", "HTTP API listener address")
	apiPort := flag.Int("api-port", 33034, "HTTP API listener port")
	keyDir := flag.String("keys-dir", filepath.Join("..", "csharp", "keys"), "authority key directory")
	checkKeys := flag.Bool("check-keys", false, "validate authority keys and exit")
	flag.Parse()

	k, err := keys.Load(*keyDir)
	if err != nil { log.Fatalf("keys: %v", err) }
	log.Printf("login authority SHA256: %s", k.LoginFingerprint)
	log.Printf("credentials authority SHA256: %s", k.CredentialsFingerprint)
	if *checkKeys { return }

	authAddr := fmt.Sprintf("%s:%d", *host, *port)
	ln, err := serveTCP(authAddr)
	if err != nil { log.Fatal(err) }
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	api := &http.Server{Addr: fmt.Sprintf("%s:%d", *apiHost, *apiPort), Handler: mux, ReadHeaderTimeout: 5*time.Second}
	go func() {
		if err := api.ListenAndServe(); err != nil && err != http.ErrServerClosed { log.Printf("api: %v", err) }
	}()

	log.Printf("experimental Go server: auth=%s api=%s", authAddr, api.Addr)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	_ = api.Close()
}
