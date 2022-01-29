//
//  This package was written by Paul Schou in Dec 2020
//
//  Originally intended as a light weight PKI authentication module to place in front of any web service
//    for doing authentication and authorization via mTLS (mutual TLS).
//
//
package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/pschou/go-params"
	"github.com/pschou/go-tease"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

var (
	target_addr                                 = ""
	keyFile, certFile, rootFile, crlURL         *string
	tls_webapp, verify_webapp, secure_webapp    *bool
	target, tls_host, listen                    *string
	verify_incoming, secure_incoming, crlBypass *bool
	enforce_handshake                           *bool
	ldapServer, baseDN, ldapFilter              *string
	debug                                       = false
	version                                     = "not set"
)

func main() {
	params.Usage = func() {
		_, prog := filepath.Split(os.Args[0])
		fmt.Fprintf(os.Stderr, "PKI Authenticator, written by Paul Schou (github.com/pschou/pki-webauth) in January 2022\n"+
			"All rights reserved, personal use only, provided AS-IS -- not responsible for loss.\n"+
			"Usage implies agreement.  Version: %s\n\nUsage: %s [options...]\n\n", version, prog)
		params.PrintDefaults()
	}
	var verbose = params.Pres("debug", "Verbose output")

	params.GroupingSet("Listener")
	{
		listen = params.String("listen", ":62871", "Listen address for PKIAUTH", "HOST:PORT")
		verify_incoming = params.Bool("verify-incoming", true, "Verify incoming certificate (if present)", "BOOL")
		secure_incoming = params.Bool("secure-incoming", true, "Enforce minimum of TLS 1.2 on connections", "BOOL")
		enforce_handshake = params.Bool("enforce-handshake", false, "Enforce mutual TLS handshakes (deny access if none is presented)", "BOOL")
	}

	params.GroupingSet("Target")
	{
		target = params.String("target", "127.0.0.1:80", "Internal webservice address for connections", "HOST:PORT")
		tls_webapp = params.Bool("tls", false, "Enable TLS connection to webservice", "BOOL")
		verify_webapp = params.Bool("verify-webservice", true, "Verify webservice, do certificate checks", "BOOL")
		secure_webapp = params.Bool("secure-webservice", true, "Enforce minimum of TLS 1.2 on webservice side", "BOOL")
		tls_host = params.String("host", "", "Hostname to verify outgoing connection with", "FQDN")
	}

	params.GroupingSet("Certificates")
	{
		certFile = params.String("cert", filepath.Join("tests", "server_cert_DONOTUSE.pem"),
			"File to load with CERT - automatically reloaded every 15 minutes\n", "FILE")
		keyFile = params.String("key", filepath.Join("tests", "server_key_DONOTUSE.pem"),
			"File to load with KEY - automatically reloaded every 15 minutes\n", "FILE")
		rootFile = params.String("ca", filepath.Join("tests", "cacerts_DONOTUSE.pem"),
			"File to load with ROOT CAs - reloaded every 15 minutes by adding any new entries\n", "FILE")
		crlURL = params.String("crl", "http://crl3.digicert.com/sha2-ev-server-g1.crl",
			"URL to load the certificate revocation list from - reloads when expired\n", "URL")
		crlBypass = params.Bool("crl-bypass", false, "If the CRL server is unavailable, allow all", "BOOL")
	}
	params.GroupingSet("LDAP - All queries are cached up to 1 hour")
	{
		ldapServer = params.String("ldap-host", "ldaps://ldap.itd.umich.edu:636", "Lookup DN entries", "PROTO://HOST:PORT")
		baseDN = params.String("basedn", "dc=umich,dc=edu", "BaseDN used to query the LDAP server", "STR")
		ldapFilter = params.String("ldap-filter", "(member={CN})", "Filter used for querying LDAP server", "FILTER")
	}

	params.CommandLine.Indent = 2
	params.Parse()

	var err error
	debug = *verbose
	rootpool = x509.NewCertPool()

	// Load pki keys and keep them refreshed in case the file changes on the disk once every 15 minutes.
	loadKeys()
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		for {
			select {
			case <-ticker.C:
				loadKeys()
			}
		}
	}()

	var (
		l      net.Listener
		config tls.Config
	)
	// Setup the config for the TLS connection used for all incoming requests.
	client_auth := tls.VerifyClientCertIfGiven
	if *enforce_handshake {
		client_auth = tls.RequireAndVerifyClientCert
	}

	if *secure_incoming {
		config = tls.Config{
			RootCAs:                  rootpool,
			Certificates:             []tls.Certificate{},
			ClientCAs:                rootpool,
			ClientAuth:               client_auth,
			InsecureSkipVerify:       !(*verify_incoming),
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			Renegotiation:            tls.RenegotiateOnceAsClient,
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}
	} else {
		config = tls.Config{RootCAs: rootpool,
			ClientAuth: client_auth, ClientCAs: rootpool, InsecureSkipVerify: !(*verify_incoming)}
	}

	// Use a call back to the local keypair for ease of refreshing
	config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if debug {
			log.Println("  Get Cert Returning keypair")
		}
		return keypair, nil
	}

	// Use stronger randomness for crypto
	config.Rand = rand.Reader
	if debug {
		log.Println("TLS Listening on", *listen)
	}
	if l, err = net.Listen("tcp", *listen); err != nil {
		log.Fatal(err)
	}

	if debug {
		log.Println("Target set to", *target)
	}
	target_addr = *target

	defer l.Close()
	for {
		conn, err := l.Accept() // Wait for a connection.
		if err != nil {
			log.Println("Error on accept", err)
			continue
		}
		if debug {
			log.Println("New connection from", conn.RemoteAddr())
		}

		// Handle the connection in a new thread
		go func(c net.Conn) {
			defer c.Close()

			// Tease the connection to determine if it is TLS or not
			teaseConn := tease.NewServer(c)
			initDat := make([]byte, 1)
			_, err := teaseConn.Read(initDat)
			if err != nil { // Return if error reading
				return
			}
			teaseConn.Replay()
			teaseConn.Pipe() // Connect the teaser to the input

			// Test for TLS header byte
			if initDat[0] == 0x16 {
				// Verify TLS and set connection
				connection(tls.Server(teaseConn, &config), c)

			} else if initDat[0] >= 'A' && initDat[0] <= 'Z' {
				// Handle as if it is an HTTP connection and try to redirect
				if debug {
					log.Println("Non-TLS connection from", conn.RemoteAddr())
				}
				redirect_to_https(teaseConn)
			}
		}(conn)
	}
}
