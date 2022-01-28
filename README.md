# PKI Authenticator - A Simple Reverse Proxy with LDAP Group Lookups

A challenge was presented to me recently to develop a method of both providing
authentication and authorization for an insitution.  This is a proof-of-concept
type of work that shows what is possible with a small footprint.

# Why would I care to use this?
* If you need an authentication method that scales with the userbase
* If you want to ensure every connection is encrypted with TLS 1.2 or higher
* If you desire two factor authentication, such as PKI certificate (and pin)
* If you want to ensure each person is associated with the proper group in the 
  application behind this authentication reverse proxy


# Usage
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
