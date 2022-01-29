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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

func connection(cli *tls.Conn, outer net.Conn) {
	cli.Handshake()
	cli.Handshake()
	conn_state := cli.ConnectionState()
	if debug {
		log.Printf("connection state: %+v\n", conn_state)
	}

	// If mTLS is enforced, kick them out
	if *enforce_handshake && !conn_state.HandshakeComplete {
		// Bye bye!
		return
	}

	// If certificate is revoked, remove the certificate
	if conn_state.HandshakeComplete {
		cert := conn_state.PeerCertificates[0]
		revoked, ok, err := certIsRevokedCRL(cert, *crlURL)
		if err != nil && debug {
			log.Printf("CRL error", err)
		}
		if !ok && *crlBypass {
			if debug {
				log.Printf("ignoring CRL")
			}
			// ignore inability to check CRL server
		} else {
			if revoked {
				print_error(cli, "Client certificate has been revoked.")
				return
			}
		}
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
		if debug && err != nil {
			log.Println("error contacting endpoint:", target_addr, "error:", err)
			return
		}
		defer webapp_conn.Close()
		webapp = (io.ReadWriter)(webapp_conn)

	} else {
		// Establish a connection to an unencrypted webapp
		webapp_conn, err := net.Dial("tcp", target_addr)
		if debug && err != nil {
			log.Println("error contacting endpoint:", target_addr, "error:", err)
			return
		}
		defer webapp_conn.Close()
		webapp = (io.ReadWriter)(webapp_conn)
	}

	if debug {
		log.Println("connected!", target_addr)
	}

	cli_buf := bufio.NewReader(cli)
	webapp_buf := bufio.NewWriter(webapp)
	webapp_buf.Write(([]byte)("test"))

	init_str, err := cli_buf.ReadString('\n')
	if err != nil {
		if debug {
			fmt.Println("Error reading client headers:", err)
		}
		return
	}
	init := strings.SplitN(init_str, " ", 3)
	if len(init) < 2 {
		return
	}
	webapp_buf.Write(([]byte)(init_str))
	//uri := init[1]
	var line string

	for err == nil {
		line, err = cli_buf.ReadString('\n')
		if len(line) > 3 && is_az(line[0]) {
			parts := strings.SplitN(line, ":", 2)
			switch strings.ToLower(parts[0]) {
			//case "host":
			//	host = strings.TrimSpace(parts[1])
			case "pkiauth-user", "pkiauth-cert-ca", "pkiauth-cert-serial",
				"pkiauth-groups", "pkiauth-remote", "pkiauth-resume", "pkiauth-handshake":
				continue
			case "user-agent":
				// Let's just drop the connection for all bad log4j / potential shell escapes, etc...
				if strings.Contains(parts[1], "${") ||
					strings.Contains(parts[1], "\\") ||
					strings.Contains(parts[1], "$(") {
					return
				}
			}
		} else if line == "\n" || line == "\r\n" {
			break
		}
		webapp_buf.Write(([]byte)(line))
	}
	if err != nil {
		if debug {
			log.Println(err)
		}
		return
	}
	if conn_state.HandshakeComplete {
		cert := conn_state.PeerCertificates[0]

		// return all the groups as a json array
		grps, err := getGroups(cert.Subject)
		jg := []byte("")
		if err == nil {
			jg, _ = json.Marshal(grps)
		}

		webapp_buf.Write(([]byte)(
			fmt.Sprintf(
				"PKIAUTH-USER: %s\nPKIAUTH-GROUPS: %s\nPKIAUTH-CERT-CA: %s\nPKIAUTH-CERT-SERIAL: %x\n",
				strings.ReplaceAll(cert.Subject.String(), "\\,", ","), jg, cert.Issuer, cert.SerialNumber)))
	}
	webapp_buf.Write(([]byte)(
		fmt.Sprintf(
			"PKIAUTH-HANDSHAKE: %t\nPKIAUTH-REMOTE: %s\nPKIAUTH-RESUME: %t\n\n",
			conn_state.HandshakeComplete, outer.RemoteAddr(), conn_state.DidResume)))

	webapp_buf.Flush()

	go io.Copy(webapp, cli_buf)
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
	// If we don't have a TLS connection, let's throw a Location block to redirect to HTTPS
	scanner := bufio.NewScanner(c)
	scanner.Scan()

	init := strings.SplitN(scanner.Text(), " ", 3)
	if len(init) < 2 {
		return
	}
	uri := init[1]
	var host string

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 3 && is_az(line[0]) {
			parts := strings.SplitN(line, ":", 2)
			switch strings.ToLower(parts[0]) {
			case "host":
				host = strings.TrimSpace(parts[1])
			case "user-agent":
				// Let's just drop all bad log4j / potential shell escapes, etc...
				// as this redirect is not the primary function of this tool.
				if strings.Contains(parts[1], "${") ||
					strings.Contains(parts[1], "\\") ||
					strings.Contains(parts[1], "$(") {
					return
				}
			}
		} else if line == "" || line == "\r" {
			break
		}
	}
	fmt.Fprintln(c, "HTTP/1.1 302 Moved Temporarily\n"+
		"Server: PKIAuth (version "+version+")\n"+
		"Content-Length: 0\n"+
		"Location: https://"+host+uri+"\n\n")

	if err := scanner.Err(); debug && err != nil {
		log.Println(err)
	}
}

// Handle consuming the headers and printing an error message
func print_error(c net.Conn, e string) {
	scanner := bufio.NewScanner(c)
	scanner.Scan()

	init := strings.SplitN(scanner.Text(), " ", 3)
	if len(init) < 2 {
		return
	}
	var host string

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 3 && is_az(line[0]) {
			parts := strings.SplitN(line, ":", 2)
			switch strings.ToLower(parts[0]) {
			case "host":
				host = strings.TrimSpace(parts[1])
			case "user-agent":
				// Let's just drop all bad log4j / potential shell escapes, etc...
				// as this redirect is not the primary function of this tool.
				if strings.Contains(parts[1], "$") ||
					strings.Contains(parts[1], "\\") ||
					strings.Contains(parts[1], "((") {
					return
				}
			}
		} else if line == "" || line == "\r" {
			break
		}
	}
	fmt.Fprintln(c, "HTTP/1.1 200 Ok\n"+
		"Server: PKIAuth (version "+version+")\n\n"+
		//		"Content-Length: "+(len()+"\n\n"+
		"<html><body><h1>Error</h1><p>"+e+"</p><p>Host: "+host+"</p></body></html>\n")

	if err := scanner.Err(); debug && err != nil {
		log.Println(err)
	}
}
