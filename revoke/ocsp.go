package revoke

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

func (c *checker) checkOCSP(ctx context.Context, cert, issuer *x509.Certificate, server string, req []byte) (revoked bool, err error) {
	var data []byte

	if len(req) > 256 {
		data, err = c.fetch(ctx, http.MethodPost, server, "application/ocsp-request", req, ocspRead, c.maxResponse)
	} else {
		data, err = c.fetch(ctx, http.MethodGet, strings.TrimSuffix(server, "/")+"/"+url.QueryEscape(base64.StdEncoding.EncodeToString(req)), "", nil, ocspRead, c.maxResponse)
	}

	if err != nil {
		return false, fmt.Errorf("failed to retrieve OCSP response: %w", err)
	}

	var resp *ocsp.Response

	if resp, err = ocsp.ParseResponseForCert(data, cert, issuer); err != nil {
		return false, fmt.Errorf("%w from %q: %w", ErrOCSPInvalid, server, err)
	}

	if err = verifyOCSP(resp, issuer, time.Now()); err != nil {
		return false, fmt.Errorf("%w from %q: %w", ErrOCSPInvalid, server, err)
	}

	switch resp.Status {
	case ocsp.Good:
		return false, nil
	case ocsp.Revoked:
		return true, nil
	default:
		return false, fmt.Errorf("%w from %q: the responder does not know the certificate", ErrOCSPInvalid, server)
	}
}

func verifyOCSP(resp *ocsp.Response, issuer *x509.Certificate, now time.Time) (err error) {
	if responder := resp.Certificate; responder != nil && !bytes.Equal(responder.Raw, issuer.Raw) {
		switch {
		case !bytes.Equal(responder.RawIssuer, issuer.RawSubject):
			return errors.New("the responder certificate was not issued by the certificate issuer")
		case !slices.Contains(responder.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning):
			return errors.New("the responder certificate is not authorized for OCSP signing")
		case now.Before(responder.NotBefore) || now.After(responder.NotAfter):
			return errors.New("the responder certificate is not within its validity period")
		}
	}

	if resp.ThisUpdate.After(now.Add(clockSkew)) {
		return fmt.Errorf("not valid until %s", resp.ThisUpdate.Format(time.RFC3339))
	}

	if !resp.NextUpdate.IsZero() && !now.Before(resp.NextUpdate) {
		return fmt.Errorf("expired at %s", resp.NextUpdate.Format(time.RFC3339))
	}

	return nil
}
