# Native client cryptographic compatibility

Update: [PATCHING.md](PATCHING.md) documents the implemented key generator,
server RSA/AES primitives and transactional patch engine. No verified patch for
the installed protected Skype EXE exists yet; the original remains unchanged.

## Brute force is not a practical implementation strategy

The repository's `skyauth4_dll/skyauth4_dll/skype/skype_basics.h` contains two relevant
public RSA moduli: 1536 bits for login and 2048 bits for credential verification.
`skype_login.c`, `Produce_Session_Key`, uses public exponent 65537. These public
numbers do not include the private decryption/signing exponents.

RSA key recovery is not like trying a small list of user passwords. General key
recovery involves integer factorization or comparably difficult cryptanalysis.
Brute-forcing correctly generated keys of these sizes is not a realistic route
for this project. RSA-1536 being below modern recommendations does not make it
practically brute-forceable on this PC.

A cheap read-only check of the two supplied moduli on 2026-09-06 gave
`gcd(login_modulus, credential_modulus) = 1`: they do not share a prime factor.
This rules out that specific easy failure, not every possible implementation flaw.
No private key was recovered, and no successful native signature bypass was found.

For context, [NIST SP 800-56B Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf)
uses RSA moduli of at least 2048 bits for at least 112-bit security strength.
That is a security-strength comparison, not a timing estimate for breaking Skype.

## Own keys require changes on both sides

A controlled private network can have its own trust authority. The server keeps
its private keys; the client must trust the corresponding public keys. A server
alone cannot tell an unchanged client to trust a new authority unless the existing
client supports an authenticated trust-update mechanism. None has been identified
in the supplied implementation.

At least these roles must be addressed:

1. Login-server RSA encryption. Replace the client's trusted login public key and
   implement recovery of the session material with the matching server private key.
2. Credential signatures. Replace the relevant trusted authority public key(s) and
   generate correctly structured credentials binding the username to the client's
   generated RSA public key. Blindly accepting all signatures is not equivalent.
3. Native authentication records. Parse login/registration, validate against SQLite,
   construct native status/credential fields, and apply the expected AES protection
   and transport framing. Changing embedded keys alone does not implement this.
4. Native profile/contact synchronization. Implement the client's actual operations;
   this repo's custom HTTP API does not automatically become compatible.

The existing wire format has fixed-size RSA fields. Generating arbitrarily larger
keys without revising that format will not work. The exact set and representation
of trusted keys in the installed 4.2.0.187 EXE still need read-only analysis before
any version-specific patch can be designed. Self-integrity/packing checks may also
affect the amount of binary adaptation required. There is no verified byte patch
in this workspace, and replacing the whole application is not inherently required.

## Eliminating hosts and redirect scripts

The current alias approach leaves the client binary intact and handles the known
IP destinations without hosts edits. It does not fix the trust-key problem.

A future client adaptation could point bootstrap/login/profile services directly
at the community server, avoiding system-wide redirection. It must account for
hardcoded endpoints, DNS names used by the client, pre-existing HostCache entries,
and addresses returned by directory/configuration responses. Replacing one IP
string in an EXE does not cover all those sources.

Client modification was discussed as an alternative, not performed in this step.
The original EXE and its private user data were not patched. Native Skype login
and registration remain unimplemented.
