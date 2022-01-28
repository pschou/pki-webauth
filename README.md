# PKI Authenticator - A Simple Reverse Proxy with LDAP Group Lookups

I was challenged to develop a lightweight method of providing authentication
and authorization for webapps that may reside on tiny devices.  This
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



# Usage
```bash
PKI Authenticator, written by Paul Schou (github.com/pschou/pki-ldap-webauth) in January 2022

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
                             (Default: "tests/ca_cert_DONOTUSE.pem")
  --cert FILE              File to load with CERT - automatically reloaded every 15 minutes
                             (Default: "tests/server_cert_DONOTUSE.pem")
  --key FILE               File to load with KEY - automatically reloaded every 15 minutes
                             (Default: "tests/server_key_DONOTUSE.pem")
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
```bash
$ ./pkiauth_linux64  --debug
2022/01/27 22:28:12 Loaded keypair tests/server_cert_DONOTUSE.pem tests/server_key_DONOTUSE.pem
 Adding CA: OU=Certificate Authority Example,O=Test Security,C=US
2022/01/27 22:28:12 Loaded CA tests/ca_cert_DONOTUSE.pem
TLS Listening on :62871
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
