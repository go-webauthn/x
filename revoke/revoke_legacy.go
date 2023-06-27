//go:build !go1.19

package revoke

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"sync"
)

// CRLSet associates a PKIX certificate list with the URL the CRL is
// fetched from.
var CRLSet = map[string]*pkix.CertificateList{}
var crlLock = new(sync.Mutex)

// fetchCRL fetches and parses a CRL.
func fetchCRL(url string) (*pkix.CertificateList, error) {
	resp, err := HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, ErrFailedGetCRL
	}

	body, err := crlRead(resp.Body)
	if err != nil {
		return nil, err
	}
	return x509.ParseCRL(body)
}

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
			return false, false, err
		}

		// check CRL signature
		if issuer != nil {
			err = issuer.CheckCRLSignature(crl)
			if err != nil {
				return false, false, err
			}
		}

		crlLock.Lock()
		CRLSet[url] = crl
		crlLock.Unlock()
	}

	for _, revoked := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			return true, true, err
		}
	}

	return false, true, err
}
