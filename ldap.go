package main

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	ldap "github.com/go-ldap/ldap"
	"log"
	"strings"
	"sync"
	"time"
)

type ldapGroups struct {
	groups []string
	query  time.Time
}

var ldapCache = make(map[string]ldapGroups)
var ldapCacheLock = new(sync.Mutex)

func getGroups(sub pkix.Name) ([]string, error) {
	dn := sub.String() //strings.ReplaceAll(sub.String(), "\\,", ",")
	ret := []string{}

	ldapCacheLock.Lock()
	if entry, ok := ldapCache[dn]; ok {
		if time.Now().Sub(entry.query) < time.Hour {
			ldapCacheLock.Unlock()
			return entry.groups, nil
		}
	}
	ldapCacheLock.Unlock()

	l, err := ldap.DialURL(*ldapServer, ldap.DialWithTLSConfig(
		&tls.Config{Certificates: []tls.Certificate{*keypair}, RootCAs: rootpool,
			ClientCAs: rootpool, InsecureSkipVerify: false, ServerName: *tls_host}),
	)
	if err != nil && debug {
		log.Println("LDAP connection error", err)
		return ret, err
	}
	defer l.Close()

	myFilt := strings.ReplaceAll(*ldapFilter, "{DN}", dn)
	myFilt = strings.ReplaceAll(myFilt, "{CN}", sub.CommonName)
	if debug {
		fmt.Println("Filter =", myFilt)
	}

	// Operations are now encrypted
	searchRequest := ldap.NewSearchRequest(
		*baseDN, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		myFilt,         // The filter to apply
		[]string{"dn"}, // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		if debug {
			log.Println("search error", err)
		}
		return ret, err
	}

	for _, entry := range sr.Entries {
		ret = append(ret, entry.DN)
		//fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue("cn"))
	}
	ldapCacheLock.Lock()
	ldapCache[dn] = ldapGroups{groups: ret, query: time.Now()}
	ldapCacheLock.Unlock()
	return ret, nil
}
