package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"
)

// HTTPClient is an instance of http.Client that will be used for all HTTP requests.
var HTTPClient = http.DefaultClient

// CRLSet associates a PKIX certificate list with the URL the CRL is
// fetched from.
var CRLSet = map[string]*pkix.CertificateList{}
var crlLock = new(sync.Mutex)

// check a cert against a specific CRL. Returns the same bool pair
// as revCheck, plus an error if one occurred.
func certIsRevokedCRL(cert *x509.Certificate, url string) (revoked, ok bool, err error) {
	crlLock.Lock()
	crl, ok := CRLSet[url]
	if ok && crl == nil {
		ok = false
		delete(CRLSet, url)
	}
	crlLock.Unlock()

	var shouldFetchCRL = true
	if ok {
		if !crl.HasExpired(time.Now()) {
			shouldFetchCRL = false
		}
	}

	issuer := getIssuer(cert)

	if shouldFetchCRL {
		var err error
		crl, err = fetchCRL(url)
		if err != nil {
			if debug {
				log.Printf("failed to fetch CRL: %v\n", err)
			}
			return false, false, err
		}

		// check CRL signature
		if issuer != nil {
			err = issuer.CheckCRLSignature(crl)
			if err != nil {
				if debug {
					log.Printf("failed to verify CRL: %v\n", err)
				}
				return false, false, err
			}
		}

		crlLock.Lock()
		CRLSet[url] = crl
		crlLock.Unlock()
	}

	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			if debug {
				log.Println("Serial number match: intermediate is revoked.", revoked.SerialNumber)
			}
			return true, true, err
		}
	}

	return false, true, err
}

// fetchCRL fetches and parses a CRL.
func fetchCRL(url string) (*pkix.CertificateList, error) {
	resp, err := HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, errors.New("failed to retrieve CRL")
	}

	body, err := crlRead(resp.Body)
	if err != nil {
		return nil, err
	}
	return x509.ParseCRL(body)
}

func getIssuer(cert *x509.Certificate) *x509.Certificate {
	var issuer *x509.Certificate
	var err error
	for _, issuingCert := range cert.IssuingCertificateURL {
		issuer, err = fetchRemote(issuingCert)
		if err != nil {
			continue
		}
		break
	}

	return issuer

}

var crlRead = ioutil.ReadAll
var remoteRead = ioutil.ReadAll

func fetchRemote(url string) (*x509.Certificate, error) {
	resp, err := HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	in, err := remoteRead(resp.Body)
	if err != nil {
		return nil, err
	}

	p, _ := pem.Decode(in)
	if p != nil {
		return x509.ParseCertificate(p.Bytes)
	}

	return x509.ParseCertificate(in)
}

/*
// ParseCertificatePEM parses and returns a PEM-encoded certificate,
// can handle PEM encoded PKCS #7 structures.
func ParseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	certPEM = bytes.TrimSpace(certPEM)
	cert, rest, err := ParseOneCertificateFromPEM(certPEM)
	if err != nil {
		// Log the actual parsing error but throw a default parse error message.
		log.Debugf("Certificate parsing error: %v", err)
		return nil, cferr.New(cferr.CertificateError, cferr.ParseFailed)
	} else if cert == nil {
		return nil, cferr.New(cferr.CertificateError, cferr.DecodeFailed)
	} else if len(rest) > 0 {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, errors.New("the PEM file should contain only one object"))
	} else if len(cert) > 1 {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ParseFailed, errors.New("the PKCS7 object in the PEM file should contain only one certificate"))
	}
	return cert[0], nil
}
*/
