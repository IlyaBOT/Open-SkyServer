package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const passwordIterations = 100000

type Database struct {
	path string
	sqlite string
	mu sync.Mutex
	docMu sync.Mutex
}

type Account struct { Login, DisplayName string }
type MessageRecord struct { ID int64; SenderLogin, RecipientLogin, Body, CreatedUTC, DeliveredUTC string }
type NativeDocument struct { Name string; Checksum uint32; Body []byte }
type NativeDocumentSnapshot struct { Revision uint32; Documents []NativeDocument }
type DirectoryTerm struct { Property, Comparison uint32; Text string; Number *uint32 }

func NewDatabase(path,sqlite string)*Database{ return &Database{path:path,sqlite:sqlite} }

func sqlQuote(v string)string{return "'"+strings.ReplaceAll(v,"'","''")+"'"}

func (d *Database) execute(sql string)(string,error){
	d.mu.Lock(); defer d.mu.Unlock()
	cmd:=exec.Command(d.sqlite,d.path,"-batch","-bail","-noheader","-tabs")
	cmd.Stdin=strings.NewReader(".timeout 5000\nPRAGMA foreign_keys=ON;\n"+sql+"\n")
	var out,er bytes.Buffer; cmd.Stdout=&out; cmd.Stderr=&er
	if err:=cmd.Run();err!=nil{return "",fmt.Errorf("sqlite failed: %v: %s",err,strings.TrimSpace(er.String()))}
	return out.String(),nil
}
func (d *Database) one(sql string)(string,error){out,e:=d.execute(sql);if e!=nil{return "",e};for _,l:=range splitLines(out){return l,nil};return "",nil}
func splitLines(s string)[]string{ s=strings.ReplaceAll(s,"\r",""); raw:=strings.Split(s,"\n"); out:=raw[:0]; for _,v:=range raw{if v!=""{out=append(out,v)}}; return out }

func (d *Database) EnsureSchema()error{
	_,err:=d.execute(`
CREATE TABLE IF NOT EXISTS accounts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
 password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_utc TEXT NOT NULL, is_active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS contacts (
 owner_login TEXT NOT NULL, contact_login TEXT NOT NULL, created_utc TEXT NOT NULL,
 PRIMARY KEY(owner_login,contact_login),
 FOREIGN KEY(owner_login) REFERENCES accounts(login) ON DELETE CASCADE,
 FOREIGN KEY(contact_login) REFERENCES accounts(login) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS native_password_verifiers (
 login TEXT PRIMARY KEY, salt TEXT NOT NULL, verifier TEXT NOT NULL,
 FOREIGN KEY(login) REFERENCES accounts(login) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS account_profiles (
 login TEXT PRIMARY KEY, email TEXT NOT NULL DEFAULT '',
 FOREIGN KEY(login) REFERENCES accounts(login) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS native_document_versions (
 login TEXT PRIMARY KEY, revision INTEGER NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 4294967295),
 FOREIGN KEY(login) REFERENCES accounts(login) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS native_documents (
 login TEXT NOT NULL, name TEXT NOT NULL, checksum INTEGER NOT NULL, body TEXT NOT NULL,
 PRIMARY KEY(login,name), UNIQUE(login,checksum),
 FOREIGN KEY(login) REFERENCES accounts(login) ON DELETE CASCADE);
CREATE TRIGGER IF NOT EXISTS native_documents_quota BEFORE INSERT ON native_documents
WHEN NOT EXISTS(SELECT 1 FROM native_documents WHERE login=NEW.login AND name=NEW.name)
AND (SELECT COUNT(*) FROM native_documents WHERE login=NEW.login)>=1024
BEGIN SELECT RAISE(ABORT,'Native document quota reached'); END;
CREATE TABLE IF NOT EXISTS sessions (
 token TEXT PRIMARY KEY, login TEXT NOT NULL, created_utc TEXT NOT NULL, last_seen_utc TEXT NOT NULL,
 FOREIGN KEY(login) REFERENCES accounts(login) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT, sender_login TEXT NOT NULL, recipient_login TEXT NOT NULL,
 body TEXT NOT NULL, created_utc TEXT NOT NULL, delivered_utc TEXT,
 FOREIGN KEY(sender_login) REFERENCES accounts(login) ON DELETE CASCADE,
 FOREIGN KEY(recipient_login) REFERENCES accounts(login) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS idx_contacts_owner ON contacts(owner_login);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_login,recipient_login,id);
`)
	if err!=nil{return err}
	rows,err:=d.execute("SELECT DISTINCT c.owner_login FROM contacts c JOIN accounts a ON a.login=c.owner_login WHERE a.is_active=1 ORDER BY c.owner_login;")
	if err!=nil{return err}
	for _,owner:=range splitLines(rows){if err:=d.EnsureNativeContactDocuments(owner);err!=nil{return err}}
	return nil
}

func pbkdf2SHA1(password,salt []byte,iter,keyLen int)[]byte{
	hLen:=sha1.Size; blocks:=(keyLen+hLen-1)/hLen; out:=make([]byte,0,blocks*hLen)
	for i:=1;i<=blocks;i++{
		m:=hmac.New(sha1.New,password); m.Write(salt); var ctr [4]byte; ctr[0]=byte(i>>24);ctr[1]=byte(i>>16);ctr[2]=byte(i>>8);ctr[3]=byte(i);m.Write(ctr[:]);u:=m.Sum(nil);t:=append([]byte(nil),u...)
		for j:=1;j<iter;j++{m=hmac.New(sha1.New,password);m.Write(u);u=m.Sum(nil);for k:=range t{t[k]^=u[k]}}
		out=append(out,t...)
	}
	return out[:keyLen]
}

func nowText()string{return time.Now().UTC().Format("2006-01-02T15:04:05.0000000Z")}

func NativePasswordDigest(login,password string)[]byte{h:=md5.Sum([]byte(login+"\nskyper\n"+password));return append([]byte(nil),h[:]...)}
func nativeVerifier(login,password string)(string,string,error){
	salt:=make([]byte,16);if _,e:=rand.Read(salt);e!=nil{return "","",e};dig:=NativePasswordDigest(login,password)
	return base64.StdEncoding.EncodeToString(salt),base64.StdEncoding.EncodeToString(pbkdf2SHA1(dig,salt,passwordIterations,32)),nil
}

func (d *Database) AddAccount(login,display,password string)error{
	if strings.TrimSpace(login)==""{return fmt.Errorf("login is required")}
	salt:=make([]byte,16);if _,e:=rand.Read(salt);e!=nil{return e}
	saltText:=base64.StdEncoding.EncodeToString(salt); hash:=base64.StdEncoding.EncodeToString(pbkdf2SHA1([]byte(password),salt,passwordIterations,32))
	nativeSalt,nativeHash,e:=nativeVerifier(login,password);if e!=nil{return e}
	exists,_:=d.one("SELECT COUNT(*) FROM accounts WHERE login="+sqlQuote(login)+";")
	var account string
	if exists!="0" && exists!="" { account="UPDATE accounts SET display_name="+sqlQuote(display)+",password_salt="+sqlQuote(saltText)+",password_hash="+sqlQuote(hash)+",is_active=1 WHERE login="+sqlQuote(login)+";" } else { account="INSERT INTO accounts(login,display_name,password_salt,password_hash,created_utc,is_active) VALUES("+sqlQuote(login)+","+sqlQuote(display)+","+sqlQuote(saltText)+","+sqlQuote(hash)+","+sqlQuote(nowText())+",1);"}
	_,e=d.execute("BEGIN IMMEDIATE;"+account+"INSERT OR REPLACE INTO native_password_verifiers(login,salt,verifier) VALUES("+sqlQuote(login)+","+sqlQuote(nativeSalt)+","+sqlQuote(nativeHash)+");COMMIT;")
	return e
}

func (d *Database) RemoveAccount(login string)error{_,e:=d.execute("DELETE FROM accounts WHERE login="+sqlQuote(login)+";");return e}

func (d *Database) GetAccount(login string)(*Account,error){
	row,e:=d.one("SELECT login,display_name FROM accounts WHERE login="+sqlQuote(login)+" AND is_active=1;");if e!=nil||row==""{return nil,e}
	p:=strings.Split(row,"\t");a:=&Account{Login:p[0],DisplayName:p[0]};if len(p)>1{a.DisplayName=p[1]};return a,nil
}

func (d *Database) AddContact(owner,contact string)error{
	a,e:=d.GetAccount(owner);if e!=nil{return e};if a==nil{return fmt.Errorf("owner account does not exist: %s",owner)}
	a,e=d.GetAccount(contact);if e!=nil{return e};if a==nil{return fmt.Errorf("contact account does not exist: %s",contact)}
	_,e=d.execute("INSERT OR IGNORE INTO contacts(owner_login,contact_login,created_utc) VALUES("+sqlQuote(owner)+","+sqlQuote(contact)+","+sqlQuote(nowText())+");")
	if e==nil{e=d.EnsureNativeContactDocuments(owner)}
	return e
}

func (d *Database) ValidatePassword(login,password string)(*Account,bool,error){
	row,e:=d.one("SELECT login,display_name,password_salt,password_hash FROM accounts WHERE login="+sqlQuote(login)+" AND is_active=1;");if e!=nil||row==""{return nil,false,e}
	p:=strings.Split(row,"\t");if len(p)<4{return nil,false,nil};salt,e:=base64.StdEncoding.DecodeString(p[2]);if e!=nil{return nil,false,e};want,e:=base64.StdEncoding.DecodeString(p[3]);if e!=nil{return nil,false,e}
	got:=pbkdf2SHA1([]byte(password),salt,passwordIterations,32);if len(want)!=len(got)||subtle.ConstantTimeCompare(want,got)!=1{return nil,false,nil}
	a:=&Account{Login:p[0],DisplayName:p[1]}
	cnt,_:=d.one("SELECT COUNT(*) FROM native_password_verifiers WHERE login="+sqlQuote(login)+";")
	if cnt=="0" {
		ns,nv,e:=nativeVerifier(login,password);if e!=nil{return nil,false,e}
		_,e=d.execute("INSERT OR IGNORE INTO native_password_verifiers(login,salt,verifier) SELECT login,"+sqlQuote(ns)+","+sqlQuote(nv)+" FROM accounts WHERE login="+sqlQuote(login)+" AND password_salt="+sqlQuote(p[2])+" AND password_hash="+sqlQuote(p[3])+" AND is_active=1;");if e!=nil{return nil,false,e}
	}
	return a,true,nil
}

func (d *Database) ValidateNativePasswordHash(login string,digest []byte)(bool,error){
	if len(digest)!=16{return false,nil}
	row,e:=d.one("SELECT v.salt,v.verifier FROM native_password_verifiers v JOIN accounts a ON a.login=v.login WHERE a.is_active=1 AND v.login="+sqlQuote(login)+";");if e!=nil||row==""{return false,e}
	p:=strings.Split(row,"\t");if len(p)!=2{return false,nil};salt,e:=base64.StdEncoding.DecodeString(p[0]);if e!=nil{return false,e};want,e:=base64.StdEncoding.DecodeString(p[1]);if e!=nil{return false,e}
	got:=pbkdf2SHA1(digest,salt,passwordIterations,32);return len(want)==len(got)&&subtle.ConstantTimeCompare(want,got)==1,nil
}

func (d *Database) RequirePassword(login,password string)error{_,ok,e:=d.ValidatePassword(login,password);if e!=nil{return e};if !ok{return fmt.Errorf("invalid credentials")};return nil}

func (d *Database) SetAccountEmail(login,email string)error{
	if len(email)>254 || strings.IndexAny(email,"\x00\r\n\t ")>=0{return fmt.Errorf("invalid account email")}
	a,e:=d.GetAccount(login);if e!=nil{return e};if a==nil{return fmt.Errorf("account does not exist")}
	_,e=d.execute("INSERT OR REPLACE INTO account_profiles(login,email) VALUES("+sqlQuote(login)+","+sqlQuote(email)+");");return e
}
func (d *Database) GetAccountEmail(login string)(string,error){a,e:=d.GetAccount(login);if e!=nil{return "",e};if a==nil{return "",fmt.Errorf("account does not exist")};return d.one("SELECT email FROM account_profiles WHERE login="+sqlQuote(login)+";")}

func (d *Database) GetContacts(owner string)([]Account,error){
	rows,e:=d.execute("SELECT a.login,a.display_name FROM contacts c JOIN accounts a ON a.login=c.contact_login WHERE c.owner_login="+sqlQuote(owner)+" AND a.is_active=1 ORDER BY a.display_name COLLATE NOCASE;");if e!=nil{return nil,e}
	var out []Account;for _,r:=range splitLines(rows){p:=strings.Split(r,"\t");if len(p)>=2{out=append(out,Account{p[0],p[1]})}};return out,nil
}

func validateDirectoryTerm(t DirectoryTerm)error{
	if t.Property==17 {if t.Comparison!=0||t.Number==nil||*t.Number!=0||t.Text!=""{return fmt.Errorf("unsupported directory logical operator")};return nil}
	if strings.TrimSpace(t.Text)==""||len([]byte(t.Text))>254{return fmt.Errorf("invalid directory query length")}
	for _,r:=range t.Text{if unicode.IsControl(r){return fmt.Errorf("control character in directory query")}}
	if t.Number!=nil{return fmt.Errorf("expected directory string value")}
	ok:=t.Property==0&&(t.Comparison==0||t.Comparison==5)||t.Property==1&&(t.Comparison==0||t.Comparison==8)||t.Property==2&&(t.Comparison==0||t.Comparison==5||t.Comparison==8||t.Comparison==9)
	if !ok{return fmt.Errorf("unsupported directory filter")}
	return nil
}

func (d *Database) SearchNativeDirectory(terms []DirectoryTerm)([]Account,error){
	if len(terms)==0||len(terms)>15{return nil,fmt.Errorf("expected directory filters")}
	var alts,preds []string;filters:=0
	for _,t:=range terms{
		if e:=validateDirectoryTerm(t);e!=nil{return nil,e}
		if t.Property==17{if len(preds)==0{return nil,fmt.Errorf("empty directory OR branch")};alts=append(alts,"("+strings.Join(preds," AND ")+")");preds=nil;continue}
		filters++;if filters>8{return nil,fmt.Errorf("too many directory filters")}
		col:="a.display_name";if t.Property==0{col="a.login"}else if t.Property==1{col="COALESCE(p.email,'')"}
		val:=sqlQuote(t.Text)
		if t.Comparison==0||t.Property==1{preds=append(preds,col+"="+val+" COLLATE NOCASE")}else if t.Comparison==5{preds=append(preds,"substr("+col+",1,length("+val+"))="+val+" COLLATE NOCASE")}else{
			words:="' '||lower(replace(replace(replace("+col+",char(9),' '),char(10),' '),char(13),' '))||' '"
			for _,w:=range strings.Fields(t.Text){suffix:="";if t.Comparison==8{suffix="||' '"};preds=append(preds,"instr("+words+",' '||lower("+sqlQuote(w)+")"+suffix+")>0")}
		}
	}
	if len(preds)==0{return nil,fmt.Errorf("empty directory OR branch")};alts=append(alts,"("+strings.Join(preds," AND ")+")")
	rows,e:=d.execute("SELECT hex(a.login),hex(a.display_name) FROM accounts a LEFT JOIN account_profiles p ON p.login=a.login WHERE a.is_active=1 AND ("+strings.Join(alts," OR ")+") ORDER BY a.login COLLATE NOCASE,a.login LIMIT 20;");if e!=nil{return nil,e}
	var out []Account
	for _,r:=range splitLines(rows){p:=strings.Split(r,"\t");if len(p)!=2{return nil,fmt.Errorf("invalid directory row")};lb,e:=hex.DecodeString(p[0]);if e!=nil{return nil,e};db,e:=hex.DecodeString(p[1]);if e!=nil{return nil,e};if !utf8.Valid(lb)||!utf8.Valid(db)||len(lb)>128||len(db)>512{return nil,fmt.Errorf("directory profile exceeds wire limits")};out=append(out,Account{string(lb),string(db)})}
	return out,nil
}

func (d *Database) GetNativeDocuments(login string)(NativeDocumentSnapshot,error){
	a,e:=d.GetAccount(login);if e!=nil{return NativeDocumentSnapshot{},e};if a==nil{return NativeDocumentSnapshot{},fmt.Errorf("account does not exist")}
	rows,e:=d.execute("SELECT COALESCE(v.revision,1),d.name,d.checksum,d.body FROM accounts a LEFT JOIN native_document_versions v ON v.login=a.login LEFT JOIN native_documents d ON d.login=a.login WHERE a.login="+sqlQuote(login)+" AND a.is_active=1 ORDER BY d.name;");if e!=nil{return NativeDocumentSnapshot{},e}
	s:=NativeDocumentSnapshot{}
	for _,r:=range splitLines(rows){p:=strings.Split(r,"\t");rev,e:=strconv.ParseUint(p[0],10,32);if e!=nil{return s,e};s.Revision=uint32(rev);if len(p)>=4&&p[1]!=""{c,_:=strconv.ParseUint(p[2],10,32);body,e:=base64.StdEncoding.DecodeString(p[3]);if e!=nil{return s,e};s.Documents=append(s.Documents,NativeDocument{p[1],uint32(c),body})}}
	if s.Revision==0{return s,fmt.Errorf("account unavailable")};return s,nil
}

func (d *Database) EnsureNativeContactDocuments(login string)error{
	d.docMu.Lock();defer d.docMu.Unlock()
	s,e:=d.GetNativeDocuments(login);if e!=nil{return e};contacts,e:=d.GetContacts(login);if e!=nil{return e}
	have:=map[string]bool{};for _,doc:=range s.Documents{have[doc.Name]=true}
	for _,c:=range contacts{n:="u/"+c.Login;if have[n]{continue};body,e:=ContactDocument(c);if e!=nil{return e};if _,e=d.putNativeDocumentUnlocked(login,n,body,CRC32Skype(body));e!=nil{return e};have[n]=true}
	return nil
}
func validateDocument(name string,body []byte,checksum uint32)error{
	if name==""||len([]byte(name))>255{return fmt.Errorf("invalid native document name")};for _,r:=range name{if unicode.IsControl(r)||r=='|'{return fmt.Errorf("invalid native document name")}}
	if len(body)==0||len(body)>12000{return fmt.Errorf("native document size limit")};if CRC32Skype(body)!=checksum{return fmt.Errorf("native document checksum mismatch")};return nil
}
func (d *Database) PutNativeDocument(login,name string,body []byte,checksum uint32)(uint32,error){d.docMu.Lock();defer d.docMu.Unlock();return d.putNativeDocumentUnlocked(login,name,body,checksum)}
func (d *Database) putNativeDocumentUnlocked(login,name string,body []byte,checksum uint32)(uint32,error){
	if e:=validateDocument(name,body,checksum);e!=nil{return 0,e};s,e:=d.GetNativeDocuments(login);if e!=nil{return 0,e};replace:=false
	for _,doc:=range s.Documents{if doc.Name==name{replace=true}else if doc.Checksum==checksum{return 0,fmt.Errorf("native document checksum collision")}}
	if !replace&&len(s.Documents)>=1024{return 0,fmt.Errorf("native document quota reached")}
	enc:=base64.StdEncoding.EncodeToString(body);cs:=strconv.FormatUint(uint64(checksum),10)
	q:="BEGIN IMMEDIATE; INSERT OR IGNORE INTO native_document_versions(login) VALUES("+sqlQuote(login)+");"+
	"UPDATE native_document_versions SET revision=revision+1 WHERE login="+sqlQuote(login)+" AND NOT EXISTS(SELECT 1 FROM native_documents WHERE login="+sqlQuote(login)+" AND name="+sqlQuote(name)+" AND checksum="+cs+" AND body="+sqlQuote(enc)+");"+
	"UPDATE native_documents SET checksum="+cs+",body="+sqlQuote(enc)+" WHERE login="+sqlQuote(login)+" AND name="+sqlQuote(name)+";"+
	"INSERT INTO native_documents(login,name,checksum,body) SELECT "+sqlQuote(login)+","+sqlQuote(name)+","+cs+","+sqlQuote(enc)+" WHERE NOT EXISTS(SELECT 1 FROM native_documents WHERE login="+sqlQuote(login)+" AND name="+sqlQuote(name)+");"+
	"SELECT revision FROM native_document_versions WHERE login="+sqlQuote(login)+"; COMMIT;"
	out,e:=d.execute(q);if e!=nil{return 0,e};v,e:=strconv.ParseUint(strings.TrimSpace(out),10,32);return uint32(v),e
}
func (d *Database) RemoveNativeDocument(login,name string)(uint32,error){
	d.docMu.Lock();defer d.docMu.Unlock();if name==""||len([]byte(name))>255{return 0,fmt.Errorf("invalid document name")};a,e:=d.GetAccount(login);if e!=nil{return 0,e};if a==nil{return 0,fmt.Errorf("account does not exist")}
	extra:="";if strings.HasPrefix(name,"u/"){extra="DELETE FROM contacts WHERE owner_login="+sqlQuote(login)+" AND contact_login="+sqlQuote(name[2:])+";"}
	out,e:=d.execute("BEGIN IMMEDIATE; INSERT OR IGNORE INTO native_document_versions(login) VALUES("+sqlQuote(login)+"); UPDATE native_document_versions SET revision=revision+1 WHERE login="+sqlQuote(login)+" AND EXISTS(SELECT 1 FROM native_documents WHERE login="+sqlQuote(login)+" AND name="+sqlQuote(name)+"); DELETE FROM native_documents WHERE login="+sqlQuote(login)+" AND name="+sqlQuote(name)+";"+extra+"SELECT revision FROM native_document_versions WHERE login="+sqlQuote(login)+"; COMMIT;");if e!=nil{return 0,e};v,e:=strconv.ParseUint(strings.TrimSpace(out),10,32);return uint32(v),e
}

func (d *Database) CreateSession(login string)(string,error){b:=make([]byte,32);if _,e:=rand.Read(b);e!=nil{return "",e};t:=base64.StdEncoding.EncodeToString(b);n:=nowText();_,e:=d.execute("INSERT INTO sessions(token,login,created_utc,last_seen_utc) VALUES("+sqlQuote(t)+","+sqlQuote(login)+","+sqlQuote(n)+","+sqlQuote(n)+");");return t,e}
func (d *Database) SendMessage(sender,recipient,body string)(int64,error){a,e:=d.GetAccount(recipient);if e!=nil{return 0,e};if a==nil{return 0,fmt.Errorf("recipient does not exist")};c,_:=d.one("SELECT COUNT(*) FROM contacts WHERE owner_login="+sqlQuote(sender)+" AND contact_login="+sqlQuote(recipient)+";");if c=="0"||c==""{return 0,fmt.Errorf("recipient is not in contact list")};row,e:=d.one("INSERT INTO messages(sender_login,recipient_login,body,created_utc) VALUES("+sqlQuote(sender)+","+sqlQuote(recipient)+","+sqlQuote(body)+","+sqlQuote(nowText())+"); SELECT last_insert_rowid();");if e!=nil{return 0,e};return strconv.ParseInt(row,10,64)}
func (d *Database) selectMessages(q string)([]MessageRecord,error){rows,e:=d.execute(q);if e!=nil{return nil,e};var out []MessageRecord;for _,r:=range splitLines(rows){p:=strings.Split(r,"\t");if len(p)<6{continue};id,_:=strconv.ParseInt(p[0],10,64);bb,_:=hex.DecodeString(p[3]);out=append(out,MessageRecord{id,p[1],p[2],string(bb),p[4],p[5]})};return out,nil}
func (d *Database) ReceiveMessages(recipient,peer string)([]MessageRecord,error){m,e:=d.selectMessages("SELECT id,sender_login,recipient_login,hex(CAST(body AS BLOB)),created_utc,COALESCE(delivered_utc,'') FROM messages WHERE sender_login="+sqlQuote(peer)+" AND recipient_login="+sqlQuote(recipient)+" AND delivered_utc IS NULL ORDER BY id;");if e!=nil{return nil,e};if len(m)>0{ids:=make([]string,len(m));for i:=range m{ids[i]=strconv.FormatInt(m[i].ID,10)};_,e=d.execute("UPDATE messages SET delivered_utc="+sqlQuote(nowText())+" WHERE id IN ("+strings.Join(ids,",")+");")};return m,e}
func (d *Database) GetHistory(login,peer string)([]MessageRecord,error){return d.selectMessages("SELECT id,sender_login,recipient_login,hex(CAST(body AS BLOB)),created_utc,COALESCE(delivered_utc,'') FROM messages WHERE (sender_login="+sqlQuote(login)+" AND recipient_login="+sqlQuote(peer)+") OR (sender_login="+sqlQuote(peer)+" AND recipient_login="+sqlQuote(login)+") ORDER BY id;")}
func (d *Database) BuildVcard(login string)string{h:=sha1.Sum([]byte(login));return "0x"+hex.EncodeToString(h[:8])+"-s127.0.0.1:33034-r127.0.0.1:33034-l127.0.0.1:33034"}

func EnsureDatabaseDirectory(path string)error{if i:=strings.LastIndexAny(path,"/\\");i>0{return os.MkdirAll(path[:i],0755)};return nil}
