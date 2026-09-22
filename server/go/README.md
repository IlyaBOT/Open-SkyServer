# Go server

Experimental Linux-friendly port of Open-SkyServer.

Implemented now:
- command-line configuration;
- loading and validation of the existing RSA XML key set;
- authority fingerprints;
- TCP auth listener shell;
- HTTP `/healthz`;
- clean SIGINT/SIGTERM shutdown.

The Skype DH/RC4/RSA/AES handlers, database/account operations, contacts, messaging and call signalling still live in the C# reference server and must be ported before this can replace it.

Build on Linux:

```bash
go build ./cmd/openskyserver
./openskyserver --keys-dir ../csharp/keys --host 0.0.0.0
```
