package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type APIServer struct {
	DB *Database
	Access *AccessPolicy
	Host string
	Port int
	sem chan struct{}
}

func apiEncode(v string)string{return strings.ReplaceAll(url.QueryEscape(v),"+","%20")}
func apiErr(w http.ResponseWriter,msg string){_,_=fmt.Fprintf(w,"ERR\t%s\n",apiEncode(msg))}
func (s *APIServer) Run()(*http.Server,error){
	s.sem=make(chan struct{},32)
	mux:=http.NewServeMux()
	mux.HandleFunc("/healthz",func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","text/plain; charset=utf-8");_,_=w.Write([]byte("ok\n"))})
	mux.HandleFunc("/",s.handle)
	srv:=&http.Server{Addr:net.JoinHostPort(s.Host,strconv.Itoa(s.Port)),Handler:mux,ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,WriteTimeout:10*time.Second}
	ln,e:=net.Listen("tcp4",srv.Addr);if e!=nil{return nil,e};log.Printf("api listening on %s",srv.Addr);go func(){if e:=srv.Serve(ln);e!=nil&&e!=http.ErrServerClosed{log.Printf("api: %v",e)}}();return srv,nil
}
func (s *APIServer) handle(w http.ResponseWriter,r *http.Request){
	w.Header().Set("Content-Type","text/plain; charset=utf-8")
	host,_,_:=net.SplitHostPort(r.RemoteAddr);if s.Access!=nil&&!s.Access.Allows(net.ParseIP(host)){http.Error(w,"forbidden",http.StatusForbidden);return}
	select{case s.sem<-struct{}{}:defer func(){<-s.sem}();default:http.Error(w,"busy",http.StatusServiceUnavailable);return}
	if r.Method!="POST"{apiErr(w,"method_not_allowed");return};if e:=r.ParseForm();e!=nil{apiErr(w,e.Error());return}
	get:=func(k string)string{return r.Form.Get(k)}
	switch r.URL.Path{
	case "/api/login":
		a,ok,e:=s.DB.ValidatePassword(get("user"),get("password"));if e!=nil{apiErr(w,e.Error());return};if !ok{apiErr(w,"invalid_credentials");return};t,e:=s.DB.CreateSession(a.Login);if e!=nil{apiErr(w,e.Error());return};fmt.Fprintf(w,"OK\n%s\t%s\n",apiEncode(t),apiEncode(a.DisplayName))
	case "/api/contacts":
		if e:=s.DB.RequirePassword(get("user"),get("password"));e!=nil{apiErr(w,e.Error());return};cs,e:=s.DB.GetContacts(get("user"));if e!=nil{apiErr(w,e.Error());return};fmt.Fprintln(w,"OK");for _,c:=range cs{fmt.Fprintf(w,"%s\t%s\t%s\n",apiEncode(c.Login),apiEncode(c.DisplayName),apiEncode(s.DB.BuildVcard(c.Login)))}
	case "/api/profile":
		if e:=s.DB.RequirePassword(get("user"),get("password"));e!=nil{apiErr(w,e.Error());return};a,e:=s.DB.GetAccount(get("target"));if e!=nil{apiErr(w,e.Error());return};if a==nil{apiErr(w,"unknown_account");return};fmt.Fprintf(w,"OK\n%s\t%s\t%s\n",apiEncode(a.Login),apiEncode(a.DisplayName),apiEncode(s.DB.BuildVcard(a.Login)))
	case "/api/myaddr":
		if e:=s.DB.RequirePassword(get("user"),get("password"));e!=nil{apiErr(w,e.Error());return};fmt.Fprint(w,"OK\n127.0.0.1\n")
	case "/api/message/send":
		if e:=s.DB.RequirePassword(get("user"),get("password"));e!=nil{apiErr(w,e.Error());return};id,e:=s.DB.SendMessage(get("user"),get("recipient"),get("body"));if e!=nil{apiErr(w,e.Error());return};fmt.Fprintf(w,"OK\n%d\n",id)
	case "/api/message/recv":
		if e:=s.DB.RequirePassword(get("user"),get("password"));e!=nil{apiErr(w,e.Error());return};m,e:=s.DB.ReceiveMessages(get("user"),get("peer"));if e!=nil{apiErr(w,e.Error());return};writeMessages(w,m)
	case "/api/history":
		if e:=s.DB.RequirePassword(get("user"),get("password"));e!=nil{apiErr(w,e.Error());return};m,e:=s.DB.GetHistory(get("user"),get("peer"));if e!=nil{apiErr(w,e.Error());return};writeMessages(w,m)
	default: apiErr(w,"unknown_endpoint")
	}
}
func writeMessages(w http.ResponseWriter,m []MessageRecord){fmt.Fprintln(w,"OK");for _,x:=range m{fmt.Fprintf(w,"%d\t%s\t%s\t%s\t%s\n",x.ID,apiEncode(x.SenderLogin),apiEncode(x.RecipientLogin),apiEncode(x.Body),apiEncode(x.CreatedUTC))}}
