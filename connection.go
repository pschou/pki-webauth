//
//  This package was written by Paul Schou in Jan 2022
//
//  This file contains the core of the utility, to handle each individual connection.
//
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

func connection(cli *tls.Conn, outer net.Conn) {
	//defer conn.Close()
	cli.Handshake()
	if debug {
		log.Printf("connection state: %+v\n", cli.ConnectionState())
	}

	var (
		webapp io.ReadWriter
		//err    error
	)

	if *tls_webapp {
		// Establish a connection to an encrypted webapp
		var tlsConfig *tls.Config
		if *secure_webapp {
			tlsConfig = &tls.Config{Certificates: []tls.Certificate{*keypair}, RootCAs: rootpool,
				ClientCAs: rootpool, InsecureSkipVerify: !(*verify_webapp), ServerName: *tls_host,
				MinVersion:               tls.VersionTLS12,
				CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				},
			}
		} else {
			tlsConfig = &tls.Config{Certificates: []tls.Certificate{*keypair}, RootCAs: rootpool,
				ClientCAs: rootpool, InsecureSkipVerify: !(*verify_webapp), ServerName: *tls_host}
		}

		tlsConfig.Rand = rand.Reader

		if debug {
			log.Println("dialing endpoint:", target_addr)
		}
		webapp_conn, err := tls.Dial("tcp", target_addr, tlsConfig)
		if err != nil {
			log.Println("error dialing endpoint:", target_addr, "error:", err)
			return
		}
		defer webapp_conn.Close()
		webapp = (io.ReadWriter)(webapp_conn)

	} else {
		// Establish a connection to an unencrypted webapp
		webapp_conn, err := net.Dial("tcp", target_addr)
		if err != nil {
			log.Println("error dialing endpoint:", target_addr, "error:", err)
			return
		}
		defer webapp_conn.Close()
		webapp = (io.ReadWriter)(webapp_conn)
	}

	if debug {
		log.Println("connected!", target_addr)
	}

	go io.Copy(webapp, cli)
	io.Copy(cli, webapp)
}

// Byte tester for alpha & numeric
func is_az(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	}
	return false
}

// Handle the unencrypted HTTP stream, pulling out the URI and HOST to make a new location block.
func redirect_to_https(c net.Conn) {
	// If we don't have a TLS connection, let's throw a Location block to redirect to https
	scanner := bufio.NewScanner(c)
	scanner.Scan()

	init := strings.SplitN(scanner.Text(), " ", 3)
	if len(init) != 3 {
		return
	}
	uri := init[1]
	var host string

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 3 && is_az(line[0]) {
			parts := strings.SplitN(line, ":", 2)
			if strings.ToLower(parts[0]) == "host" {
				host = strings.TrimSpace(parts[1])
			}
		} else if line == "" || line == "\r" {
			fmt.Fprintln(c, "HTTP/1.1 302 Moved Temporarily\n"+
				"Server: PKIAuth (version "+version+")\n"+
				"Content-Length: 0\n"+
				"Location: https://"+host+uri+"\n\n")
			return
		}
	}

	if err := scanner.Err(); debug && err != nil {
		log.Println(err)
	}
}
