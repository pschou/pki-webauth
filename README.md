# PKI Authenticator - A Simple Reverse Proxy Using PKI for Authentication and LDAP for Authorization

I was challenged to develop a lightweight method of providing authentication
and authorization for webapps that may reside on integrated devices.  This
proof-of-concept type of work shows what is possible with PKI authentication
and fit within a small footprint.

This tool takes an incoming client mTLS request and then presents the client
information to a webapp sitting behind this authentication and encryption
layer.  The server behind this tool can be listening on any port and be either
HTTP or HTTPS.  Thus, using this authenticator, one can rest assured that all
connections coming in will be fully encrypted, and user authentication details
can be handled externally and presented to the underlying webapp.

# Why would I care to use this?
* If you need an authentication method that scales with the userbase
* If you want to ensure every connection is encrypted with TLS 1.2 or higher
* If you desire two-factor authentication, such as PKI certificate (and pin)
* If you want to ensure each person is associated with the proper group in the
  application behind this authentication reverse proxy
* This reverse proxy blocks Log4j and other user-agent escapes.

# Comparing PKI to tokens:
* Tokens are issued and maintained by a central token issuing server 
* PKI use the person’s identity provided by the certificate and the reverse
  proxy maintains the authorization levels needed for the use of that webapp
* Tokens rely on cookies and are relevant to a user’s session, meaning if a
  person’s session token is compromised, the attacker can assume the role of
that person
* PKI cards are physical and are locked down once removed from a reader with a
  PIN.  The act of removing the card locks the smart chip to prevent usage
* Tokens require back and forth between the authentication server and a webapp
* PKI with this reverse proxy, is a single connection from the user’s
  perspective.  Less is more as the user can connect to any resource directly,
establish the TLS tunnel encryption, and then with a second handshake, the
user’s identity.  If the user is on an open Wi-Fi connection or high latent
link, it is one connection, not multiple.



# Usage
```bash
PKI Authenticator, written by Paul Schou (github.com/pschou/pki-webauth) in January 2022

Usage: pkiauth_linux64 [options...]

Option:
  --debug                  Verbose output
Listener options:
  --enforce-handshake BOOL  Enforce mutual TLS handshakes (deny access if none is presented)  (Default: false)
  --listen HOST:PORT       Listen address for PKIAUTH  (Default: ":62871")
  --secure-incoming BOOL   Enforce minimum of TLS 1.2 on connections  (Default: true)
  --verify-incoming BOOL   Verify incoming certificate (if present)  (Default: true)
Target options:
  --host FQDN              Hostname to verify outgoing connection with  (Default: "")
  --secure-webservice BOOL  Enforce minimum of TLS 1.2 on webservice side  (Default: true)
  --target HOST:PORT       Internal webservice address for connections  (Default: "127.0.0.1:80")
  --tls BOOL               Enable TLS connection to webservice  (Default: false)
  --verify-webservice BOOL  Verify webservice, do certificate checks  (Default: true)
Certificates options:
  --ca FILE                File to load with ROOT CAs - reloaded every 15 minutes by adding any new entries
                             (Default: "tests/cacerts_DONOTUSE.pem")
  --cert FILE              File to load with CERT - automatically reloaded every 15 minutes
                             (Default: "tests/server_cert_DONOTUSE.pem")
  --crl URL                URL to load the certificate revocation list from - reloads when expired
                             (Default: "http://crl3.digicert.com/sha2-ev-server-g1.crl")
  --crl-bypass BOOL        If the CRL server is unavailable, allow all  (Default: false)
  --key FILE               File to load with KEY - automatically reloaded every 15 minutes
                             (Default: "tests/server_key_DONOTUSE.pem")
LDAP - All queries are cached up to 1 hour options:
  --basedn USER            BaseDN used to query the LDAP server  (Default: "dc=umich,dc=edu")
  --ldap-filter FILTER     Filter used for querying LDAP server  (Default: "(member={CN})")
  --ldap-host PROTO://HOST:PORT  Lookup DN entries  (Default: "ldaps://ldap.itd.umich.edu:636")
```

To run the reverse proxy, listening on the default port :62871 use
```
pkiauth
```

Else if you want to specify a port use
```
pkiauth --listen :2000
```

Or listen on a specific port and host:
```
pkiauth --listen 1.2.3.4:2000
```

# Example of usage

Now to test, let's open one screen and start the server:
```
$ ./pkiauth_linux64  --debug
2022/01/28 16:22:02 Loaded keypair tests/server_cert_DONOTUSE.pem tests/server_key_DONOTUSE.pem
 Adding CA: CN=InCommon RSA Server CA,OU=InCommon,O=Internet2,L=Ann Arbor,ST=MI,C=US
 Adding CA: OU=Certificate Authority Example,O=Test Security,C=US
2022/01/28 16:22:02 Loaded CA tests/cacerts_DONOTUSE.pem
2022/01/28 16:22:02 TLS Listening on :62871
2022/01/28 16:22:02 Target set to 127.0.0.1:80
2022/01/28 16:22:05 New connection from [::1]:40796
2022/01/28 16:22:05 Non-TLS connection from [::1]:40796
2022/01/28 16:22:05 New connection from [::1]:40798
2022/01/28 16:22:05   Get Cert Returning keypair
2022/01/28 16:22:05 connection state: {Version:771 HandshakeComplete:true DidResume:false CipherSuite:49200 NegotiatedProtocol: NegotiatedProtocolIsMutual:true ServerName:localhost PeerCertificates:[0xc0001c9600] VerifiedChains:[[0xc0001c9600 0xc0001c9080]] SignedCertificateTimestamps:[] OCSPResponse:[] TLSUnique:[51 68 31 123 81 10 231 201 94 202 94 34] ekm:0x5ddfa0}
2022/01/28 16:22:05 connected! 127.0.0.1:80
```

From a second terminal, try a query into that server using curl:
```bash
curl -L -vvv --cacert tests/ca_cert_DONOTUSE.pem --cert tests/npe1_cert_DONOTUSE.pem --key tests/npe1_key_DONOTUSE.pem https://localhost:62871
```

If you prefer to use openssl directy:
```bash
openssl s_client -connect localhost:62871 -CAfile tests/ca_cert_DONOTUSE.pem -cert tests/npe1_cert_DONOTUSE.pem -key tests/npe1_key_DONOTUSE.pem
```

A fancy thing will happen if you request http from the https endpoint, it will send a redirect back to you to request the https version on the same port:
```bash
curl -L -vvv --cacert tests/ca_cert_DONOTUSE.pem --cert tests/npe1_cert_DONOTUSE.pem --key tests/npe1_key_DONOTUSE.pem http://localhost:62871
```

Now watch the output on both terminals handle the connection.  Bo yeah, connection, reverse proxy, and PKI Authentication magic all in package less than 10MB and super portable!


Here is an example of what the webapp will see in the header:
```
GET / HTTP/1.1
User-Agent: curl/7.29.0
Host: localhost:62871
Accept: */*
PKIAUTH-USER: CN=uid=ppena,ou=people,dc=umich,dc=edu
PKIAUTH-GROUPS: ["cn=Campus DHCP WIKI read,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=csg-macbuild,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=CSG Staff,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=csg-temps,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=LSATS MLB,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=LSA TS Research Computing and Infrastructure Managed,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=LSA Technology Services Full Time Staff Managed,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=MLB Build Notification,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=LSATS-RCI-LSA,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=LSATS-RCI-MLB-temps,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=TDX-LSA-TS-DesktopSupportTeam,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=TDX-LSA-TS-DesktopSupport-LSA,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=TDX-LSA-TS-DesktopSupport-MLB,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=ServiceNow Archive Units,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=Michigan IT Slack,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=LSA TS Steamline Upgrade WorkGroup,ou=User Groups,ou=Groups,dc=umich,dc=edu","cn=Computer Support Group test,ou=User Groups,ou=Groups,dc=umich,dc=edu"]
PKIAUTH-CERT-CA: OU=Certificate Authority Example,O=Test Security,C=US
PKIAUTH-CERT-SERIAL: 2114
PKIAUTH-HANDSHAKE: true
PKIAUTH-REMOTE: [::1]:40798
PKIAUTH-RESUME: false
```
