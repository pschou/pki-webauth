package main

import (
	//"crypto/tls"
	"crypto/x509/pkix"
	ldap "github.com/go-ldap/ldap"
	"log"
)

func getGroups(sub pkix.Name) (ret []string) {
	ret = []string{}
	l, err := ldap.DialURL(*ldapServer)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	//fmt.Printf("ldap: %+v\n", sub)
	// Reconnect with TLS
	//err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	//if err != nil {
	//	log.Fatal(err)
	//}

	// Operations are now encrypted
	searchRequest := ldap.NewSearchRequest(
		*baseDN, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(member="+sub.CommonName+")", // The filter to apply
		[]string{"dn"},                // A list attributes to retrieve
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		if debug {
			log.Println("search error", err)
		}
		return
	}

	for _, entry := range sr.Entries {
		ret = append(ret, entry.DN)
		//fmt.Printf("%s: %v\n", entry.DN, entry.GetAttributeValue("cn"))
	}
	return ret
}
