package revoke

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

func NewVerifier(opts ...VerifierOption) (verifier *Verifier) {
	verifier = &Verifier{
		client: &http.Client{},
		crls:   map[string]*x509.RevocationList{},
		lock:   &sync.Mutex{},
		reader: io.ReadAll,
	}

	for _, opt := range opts {
		opt(verifier)
	}

	return verifier
}

type Verifier struct {
	client *http.Client
	crls   map[string]*x509.RevocationList
	lock   *sync.Mutex
	strict bool

	reader     Reader
	readerCRL  Reader
	readerOCSP Reader
}

func (v *Verifier) CertificateValid(cert *x509.Certificate) (revoked, ok bool, err error) {
	if !time.Now().Before(cert.NotAfter) {
		return true, true, fmt.Errorf("Certificate expired %s\n", cert.NotAfter)
	} else if !time.Now().After(cert.NotBefore) {
		return true, true, fmt.Errorf("Certificate isn't valid until %s\n", cert.NotBefore)
	}

	return v.CertificateRevoked(cert)
}

func (v *Verifier) CertificateRevoked(cert *x509.Certificate) (revoked, ok bool, err error) {
	for _, uri := range cert.CRLDistributionPoints {
		if ldapURL(uri) {
			continue
		}

		if revoked, ok, err = v.CertificateRevokedCRL(cert, uri); !ok {
			if v.strict {
				return true, false, err
			}

			return false, false, err
		} else if revoked {
			return true, true, err
		}
	}

	if revoked, ok, err = v.CertificateRevokedOCSP(cert); !ok {
		if v.strict {
			return true, false, err
		}

		return false, false, err
	} else if revoked {
		return true, true, err
	}

	return false, true, nil
}

func (v *Verifier) CertificateRevokedCRL(cert *x509.Certificate, uri string) (revoked, ok bool, err error) {
	var crl *x509.RevocationList

	v.lock.Lock()

	if crl, ok = v.crls[uri]; ok && crl == nil {
		ok = false

		delete(v.crls, uri)
	}

	defer v.lock.Unlock()

	var shouldFetchCRL = true

	if ok && time.Now().Before(crl.NextUpdate) {
		shouldFetchCRL = false
	}

	issuer := v.GetIssuer(cert)

	if shouldFetchCRL {
		if crl, err = v.fetchCRL(uri); err != nil {
			return false, false, err
		}

		// Check the CRL signature.
		if issuer != nil {
			if err = crl.CheckSignatureFrom(issuer); err != nil {
				return false, false, err
			}
		}

		v.crls[uri] = crl
	}

	for _, rcert := range crl.RevokedCertificateEntries {
		if cert.SerialNumber.Cmp(rcert.SerialNumber) == 0 {
			return true, true, err
		}
	}

	return false, true, err
}

func (v *Verifier) CertificateRevokedOCSP(cert *x509.Certificate) (revoked, ok bool, e error) {
	var err error

	ocspURLs := cert.OCSPServer
	if len(ocspURLs) == 0 {
		// OCSP not enabled for this certificate.
		return false, true, nil
	}

	issuer := v.GetIssuer(cert)

	if issuer == nil {
		return false, false, nil
	}

	req, err := ocsp.CreateRequest(cert, issuer, &ocspOpts)
	if err != nil {
		return revoked, ok, err
	}

	var resp *ocsp.Response

	for _, server := range ocspURLs {
		if resp, err = v.fetchOCSP(server, req, cert, issuer); err != nil {
			if v.strict {
				return revoked, ok, err
			}

			continue
		}

		// There wasn't an error fetching the OCSP status.
		ok = true

		if resp.Status != ocsp.Good {
			// The certificate was revoked.
			revoked = true
		}

		return revoked, ok, err
	}

	return revoked, ok, err
}

func (v *Verifier) GetIssuer(cert *x509.Certificate) (issuer *x509.Certificate) {
	var (
		uri string
		err error
	)

	for _, uri = range cert.IssuingCertificateURL {
		if issuer, err = v.fetchCert(uri); err != nil {
			continue
		}

		break
	}

	return issuer
}

func (v *Verifier) readfunc(r Reader) (reader Reader) {
	if r != nil {
		return r
	}

	return v.reader
}

func (v *Verifier) fetch(url string, read Reader) (resp *http.Response, body []byte, err error) {
	if resp, err = v.client.Get(url); err != nil {
		return nil, nil, err
	}

	defer resp.Body.Close()

	if body, err = read(resp.Body); err != nil {
		return nil, nil, err
	}

	return resp, body, nil
}

func (v *Verifier) fetchCert(url string) (cert *x509.Certificate, err error) {
	var (
		body []byte
	)

	if _, body, err = v.fetch(url, v.reader); err != nil {
		return nil, err
	}

	if p, _ := pem.Decode(body); p != nil {
		return ParseCertificatePEM(body)
	}

	return x509.ParseCertificate(body)
}

// fetchCRL fetches and parses a CRL.
func (v *Verifier) fetchCRL(url string) (crl *x509.RevocationList, err error) {
	var (
		resp *http.Response
		body []byte
	)

	if resp, body, err = v.fetch(url, v.readfunc(v.readerCRL)); err != nil {
		return nil, err
	}

	if resp.StatusCode >= 300 {
		return nil, ErrFailedGetCRL
	}

	return x509.ParseRevocationList(body)
}

func (v *Verifier) fetchOCSP(server string, req []byte, leaf, issuer *x509.Certificate) (r *ocsp.Response, err error) {
	var resp *http.Response

	if len(req) > 256 {
		buf := bytes.NewBuffer(req)
		resp, err = v.client.Post(server, "application/ocsp-request", buf)
	} else {
		reqURL := server + "/" + url.QueryEscape(base64.StdEncoding.EncodeToString(req))
		resp, err = v.client.Get(reqURL)
	}

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve OSCP")
	}

	body, err := v.readfunc(v.readerOCSP)(resp.Body)
	if err != nil {
		return nil, err
	}

	switch {
	case bytes.Equal(body, ocsp.UnauthorizedErrorResponse):
		return nil, errors.New("OSCP unauthorized")
	case bytes.Equal(body, ocsp.MalformedRequestErrorResponse):
		return nil, errors.New("OSCP malformed")
	case bytes.Equal(body, ocsp.InternalErrorErrorResponse):
		return nil, errors.New("OSCP internal error")
	case bytes.Equal(body, ocsp.TryLaterErrorResponse):
		return nil, errors.New("OSCP try later")
	case bytes.Equal(body, ocsp.SigRequredErrorResponse):
		return nil, errors.New("OSCP signature required")
	}

	return ocsp.ParseResponseForCert(body, leaf, issuer)
}

type VerifierOption func(validator *Verifier)

func WithClient(client *http.Client) VerifierOption {
	return func(validator *Verifier) {
		validator.client = client
	}
}

func WithStrict() VerifierOption {
	return func(validator *Verifier) {
		validator.strict = true
	}
}

func WithReader(reader Reader) VerifierOption {
	return func(validator *Verifier) {
		validator.reader = reader
	}
}

func WithCRLReader(reader Reader) VerifierOption {
	return func(validator *Verifier) {
		validator.readerCRL = reader
	}
}

func WithOCSPReader(reader Reader) VerifierOption {
	return func(validator *Verifier) {
		validator.readerOCSP = reader
	}
}

type Reader func(r io.Reader) ([]byte, error)

var (
	ocspOpts = ocsp.RequestOptions{
		Hash: crypto.SHA1,
	}
)
