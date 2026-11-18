package revoke

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func TestVerifierVerifyCertificate(t *testing.T) {
	testCases := []struct {
		name    string
		setup   func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate)
		revoked bool
		ok      bool
		err     error
	}{
		{
			name: "ShouldPermitCertificateNotOnCRL",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, nil, big.NewInt(1)))

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldPermitCertificateNotOnPEMEncodedCRL",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: newCRL(t, e.ca, e.caKey, nil)}))

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldRejectCertificateOnCRL",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, nil, cert.SerialNumber))

				return cert, e.ca
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldNotTrustCRLForgedByIssuerWithSameName",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.attacker, e.attackerKey, nil))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldNotTrustCRLFromAnotherIssuer",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				other, otherKey := newCA(t, "Other CA")

				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, other, otherKey, nil))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldNotTrustMalformedCRL",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set([]byte("not a crl"))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldNotTrustExpiredCRL",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, func(template *x509.RevocationList) {
					template.ThisUpdate = time.Now().Add(-2 * time.Hour)
					template.NextUpdate = time.Now().Add(-time.Hour)
				}))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldNotTrustCRLWithoutNextUpdate",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newUndatedCRL(t, e.ca, e.caKey))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldUseOCSPWhenCRLHasNoNextUpdate",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL), withOCSP(e.ocsp.URL))
				e.crl.set(newUndatedCRL(t, e.ca, e.caKey))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Revoked, nil))

				return cert, e.ca
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldNotTrustCRLWhichExpiresWhileRetrieved",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				next := time.Now().Truncate(time.Second).Add(2 * time.Second)

				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.delay = time.Until(next) + 200*time.Millisecond
				e.crl.set(newCRL(t, e.ca, e.caKey, func(template *x509.RevocationList) {
					template.NextUpdate = next
				}))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldNotTrustCRLWithUnsupportedCriticalEntryExtension",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, func(template *x509.RevocationList) {
					template.RevokedCertificateEntries[0].ExtraExtensions = []pkix.Extension{
						{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Critical: true, Value: []byte{0x05, 0x00}},
					}
				}, big.NewInt(1)))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldNotTrustCRLWithCertificateIssuerEntryExtension",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				value, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: e.ca.RawSubject}})
				require.NoError(t, err)

				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, func(template *x509.RevocationList) {
					template.RevokedCertificateEntries[0].ExtraExtensions = []pkix.Extension{
						{Id: oidExtensionCertificateIssuer, Critical: true, Value: value},
					}
				}, big.NewInt(1)))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldRejectCertificateOnCRLWithSupportedEntryExtensions",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, func(template *x509.RevocationList) {
					template.RevokedCertificateEntries[0].ReasonCode = 1
					template.RevokedCertificateEntries[0].ExtraExtensions = []pkix.Extension{
						{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: []byte{0x05, 0x00}},
					}
				}, cert.SerialNumber))

				return cert, e.ca
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldNotTrustDeltaCRL",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				value, err := asn1.Marshal(1)
				require.NoError(t, err)

				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, func(template *x509.RevocationList) {
					template.ExtraExtensions = []pkix.Extension{{Id: oidExtensionDeltaCRLIndicator, Critical: true, Value: value}}
				}))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldNotTrustCRLScopedToAnotherDistributionPoint",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, withScope(t, issuingDistributionPoint{
					DistributionPoint: distributionPointName{FullName: []asn1.RawValue{uriName("http://crl.example.com/other.crl")}},
				})))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldNotTrustCRLScopedToCACertificates",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, withScope(t, issuingDistributionPoint{OnlyContainsCACerts: true})))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldPermitCRLScopedToDistributionPoint",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, withScope(t, issuingDistributionPoint{
					DistributionPoint:     distributionPointName{FullName: []asn1.RawValue{uriName(e.crl.URL)}},
					OnlyContainsUserCerts: true,
				})))

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldPermitCRLScopedToUserCertificatesWithoutDistributionPoint",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, withRawScope([]byte{0x30, 0x03, 0x81, 0x01, 0xff})))

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldNotTrustCRLScopedToUserCertificatesWithoutDistributionPointForCA",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert, _ = newCertificate(t, e.ca, e.caKey, withCRL(e.crl.URL), withCA)
				e.crl.set(newCRL(t, e.ca, e.caKey, withRawScope([]byte{0x30, 0x03, 0x81, 0x01, 0xff})))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldRejectCertificateOnCRLScopedToSomeReasons",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, withScope(t, issuingDistributionPoint{OnlySomeReasons: keyCompromiseOnly}), cert.SerialNumber))

				return cert, e.ca
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldNotDetermineStatusWhenNotOnCRLScopedToSomeReasons",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, withScope(t, issuingDistributionPoint{OnlySomeReasons: keyCompromiseOnly}), big.NewInt(1)))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldUseOCSPWhenNotOnCRLScopedToSomeReasons",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL), withOCSP(e.ocsp.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, withScope(t, issuingDistributionPoint{OnlySomeReasons: keyCompromiseOnly})))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Good, nil))

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldNotTrustCRLScopedToSomeReasonsAndCACertificates",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, withScope(t, issuingDistributionPoint{OnlyContainsCACerts: true, OnlySomeReasons: keyCompromiseOnly}), cert.SerialNumber))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldNotDetermineStatusWhenCRLUnavailable",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				e.crl.status = http.StatusNotFound

				return e.issue(t, withCRL(e.crl.URL)), e.ca
			},
			err: ErrFailedGetCRL,
		},
		{
			name: "ShouldNotDetermineStatusWithoutIssuer",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, nil))

				return cert, nil
			},
			err: ErrNoIssuer,
		},
		{
			name: "ShouldNotDetermineStatusWithIssuerWhichDidNotIssueCertificate",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.attacker, e.attackerKey, nil))

				return cert, e.attacker
			},
			err: ErrIssuerMismatch,
		},
		{
			name: "ShouldNotDetermineStatusWithIssuerWhichCopiesSubjectKeyID",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				forged, forgedKey := newCA(t, "Test CA", func(template *x509.Certificate) {
					template.SubjectKeyId = e.ca.SubjectKeyId
				})

				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, forged, forgedKey, nil))

				return cert, forged
			},
			err: ErrIssuerMismatch,
		},
		{
			name: "ShouldRejectCertificateOnCRLOfReissuedIssuerWithAnotherSubjectKeyID",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				issuer = reissueCA(t, e.ca, e.caKey)

				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, issuer, e.caKey, nil, cert.SerialNumber))

				require.NotEqual(t, cert.AuthorityKeyId, issuer.SubjectKeyId)

				return cert, issuer
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldPermitCertificateNotOnCRLOfReissuedIssuerWithAnotherSubjectKeyID",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				issuer = reissueCA(t, e.ca, e.caKey)

				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, issuer, e.caKey, nil))

				return cert, issuer
			},
			ok: true,
		},
		{
			name: "ShouldPermitCertificateWithoutRevocationSources",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				return e.issue(t), e.ca
			},
			ok: true,
		},
		{
			name: "ShouldNotDetermineStatusWithOnlyUnsupportedSources",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				return e.issue(t, withCRL("ldap://ldap.example.com/cn=ca?certificateRevocationList")), e.ca
			},
			err: ErrNoSupportedSource,
		},
		{
			name: "ShouldSkipUnsupportedSources",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL("ldap://ldap.example.com/cn=ca?certificateRevocationList", e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, nil, cert.SerialNumber))

				return cert, e.ca
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldRejectCertificateOnCRLOfLaterDistributionPoint",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				second := newTestServer(t)

				cert = e.issue(t, withCRL(e.crl.URL, second.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, nil, big.NewInt(1)))
				second.set(newCRL(t, e.ca, e.caKey, nil, cert.SerialNumber))

				return cert, e.ca
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldRejectCertificateOnCRLOfLaterDistributionPointWhenEarlierUnavailable",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				second := newTestServer(t)

				e.crl.status = http.StatusNotFound

				cert = e.issue(t, withCRL(e.crl.URL, second.URL))
				second.set(newCRL(t, e.ca, e.caKey, nil, cert.SerialNumber))

				return cert, e.ca
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldPermitCertificateNotOnCRLOfAnyDistributionPoint",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				second := newTestServer(t)

				cert = e.issue(t, withCRL(e.crl.URL, second.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, nil, big.NewInt(1)))
				second.set(newCRL(t, e.ca, e.caKey, nil, big.NewInt(2)))

				t.Cleanup(func() {
					assert.Equal(t, int64(1), second.hits.Load())
				})

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldPermitCertificateNotOnCRLWhenEarlierDistributionPointUnavailable",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				second := newTestServer(t)

				e.crl.status = http.StatusNotFound

				cert = e.issue(t, withCRL(e.crl.URL, second.URL))
				second.set(newCRL(t, e.ca, e.caKey, nil))

				t.Cleanup(func() {
					assert.Equal(t, int64(1), second.hits.Load())
				})

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldPermitCertificateNotOnCRLWhenLaterDistributionPointCanNotBeAuthenticated",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				second := newTestServer(t)

				cert = e.issue(t, withCRL(e.crl.URL, second.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, nil))
				second.set(newCRL(t, e.attacker, e.attackerKey, nil, cert.SerialNumber))

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldNotDetermineStatusWhenNoDistributionPointCanBeAuthenticated",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				second := newTestServer(t)

				e.crl.status = http.StatusNotFound

				cert = e.issue(t, withCRL(e.crl.URL, second.URL))
				second.set(newCRL(t, e.attacker, e.attackerKey, nil))

				return cert, e.ca
			},
			err: ErrCRLInvalid,
		},
		{
			name: "ShouldRejectOversizedCRL",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				v.MaxCRLSize = 64

				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, nil))

				return cert, e.ca
			},
			err: ErrResponseTooLarge,
		},
		{
			name: "ShouldRejectOversizedCRLWithoutContentLength",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				v.MaxCRLSize = 64
				e.crl.chunked = true

				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.ca, e.caKey, nil))

				return cert, e.ca
			},
			err: ErrResponseTooLarge,
		},
		{
			name: "ShouldTimeoutHangingCRLServer",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				v.Timeout = 100 * time.Millisecond
				e.crl.hang = true

				return e.issue(t, withCRL(e.crl.URL)), e.ca
			},
			err: context.DeadlineExceeded,
		},
		{
			name: "ShouldPermitCertificateWithGoodOCSPStatus",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Good, nil))

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldRejectCertificateWithRevokedOCSPStatus",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Revoked, nil))

				return cert, e.ca
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldNotDetermineStatusWithUnknownOCSPStatus",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Unknown, nil))

				return cert, e.ca
			},
			err: ErrOCSPInvalid,
		},
		{
			name: "ShouldNotDetermineStatusWithOCSPErrorResponse",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				e.ocsp.set(ocsp.UnauthorizedErrorResponse)

				return e.issue(t, withOCSP(e.ocsp.URL)), e.ca
			},
			err: ErrOCSPInvalid,
		},
		{
			name: "ShouldNotTrustOCSPResponseSignedByAnotherIssuer",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.attacker, e.attacker, e.attackerKey, cert, ocsp.Good, nil))

				return cert, e.ca
			},
			err: ErrOCSPInvalid,
		},
		{
			name: "ShouldPermitOCSPResponseSignedByDelegatedResponder",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				responder, responderKey := newCertificate(t, e.ca, e.caKey, withOCSPSigning)

				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, responder, responderKey, cert, ocsp.Good, nil))

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldNotTrustOCSPResponderDelegatedByAnotherIssuer",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				responder, responderKey := newCertificate(t, e.attacker, e.attackerKey, withOCSPSigning)

				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.attacker, responder, responderKey, cert, ocsp.Good, nil))

				return cert, e.ca
			},
			err: ErrOCSPInvalid,
		},
		{
			name: "ShouldNotTrustOCSPResponderWithoutOCSPSigningUsage",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				responder, responderKey := newCertificate(t, e.ca, e.caKey)

				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, responder, responderKey, cert, ocsp.Good, nil))

				return cert, e.ca
			},
			err: ErrOCSPInvalid,
		},
		{
			name: "ShouldNotTrustExpiredOCSPResponse",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Good, func(template *ocsp.Response) {
					template.ThisUpdate = time.Now().Add(-2 * time.Hour)
					template.NextUpdate = time.Now().Add(-time.Hour)
				}))

				return cert, e.ca
			},
			err: ErrOCSPInvalid,
		},
		{
			name: "ShouldPermitFreshOCSPResponseWithoutNextUpdate",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Good, func(template *ocsp.Response) {
					template.NextUpdate = time.Time{}
				}))

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldNotTrustStaleOCSPResponseWithoutNextUpdate",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Good, func(template *ocsp.Response) {
					template.ThisUpdate = time.Now().Add(-DefaultMaxOCSPAge - time.Hour)
					template.NextUpdate = time.Time{}
				}))

				return cert, e.ca
			},
			err: ErrOCSPInvalid,
		},
		{
			name: "ShouldNotTrustOCSPResponseWithoutNextUpdateOlderThanConfiguredAge",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				v.MaxOCSPAge = 30 * time.Minute

				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Good, func(template *ocsp.Response) {
					template.NextUpdate = time.Time{}
				}))

				return cert, e.ca
			},
			err: ErrOCSPInvalid,
		},
		{
			name: "ShouldPermitOCSPResponseWithNextUpdateOlderThanConfiguredAge",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				v.MaxOCSPAge = 30 * time.Minute

				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Good, nil))

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldNotTrustOCSPResponseForCertificateOfAnotherIssuer",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				other, _ := newCA(t, "Other CA")

				// The response is signed by the issuer, but gives the status of the same serial number of another issuer.
				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, other, e.ca, e.caKey, cert, ocsp.Good, func(template *ocsp.Response) {
					template.Certificate = nil
				}))

				return cert, e.ca
			},
			err: ErrOCSPInvalid,
		},
		{
			name: "ShouldNotTrustOCSPResponseForCertificateOfIssuerWithSameName",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.attacker, e.ca, e.caKey, cert, ocsp.Good, func(template *ocsp.Response) {
					template.Certificate = nil
				}))

				return cert, e.ca
			},
			err: ErrOCSPInvalid,
		},
		{
			name: "ShouldPermitOCSPResponseWithEmbeddedSelfSignedIssuer",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Good, func(template *ocsp.Response) {
					template.Certificate = e.ca
				}))

				return cert, e.ca
			},
			ok: true,
		},
		{
			name: "ShouldRejectCertificateWithOCSPResponseWithEmbeddedIntermediateIssuer",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				intermediate, intermediateKey := newCertificate(t, e.ca, e.caKey, withCA)

				cert, _ = newCertificate(t, intermediate, intermediateKey, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, intermediate, intermediate, intermediateKey, cert, ocsp.Revoked, func(template *ocsp.Response) {
					template.Certificate = intermediate
				}))

				return cert, intermediate
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldNotTrustOCSPResponseWithEmbeddedIssuerSignedByAnotherKey",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				intermediate, intermediateKey := newCertificate(t, e.ca, e.caKey, withCA)

				cert, _ = newCertificate(t, intermediate, intermediateKey, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, intermediate, intermediate, e.attackerKey, cert, ocsp.Good, func(template *ocsp.Response) {
					template.Certificate = intermediate
				}))

				return cert, intermediate
			},
			err: ErrOCSPInvalid,
		},
		{
			name: "ShouldNotTrustOCSPResponseWithoutEmbeddedCertificateSignedByAnotherKey",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.attackerKey, cert, ocsp.Good, nil))

				return cert, e.ca
			},
			err: ErrOCSPInvalid,
		},
		{
			name: "ShouldRejectOversizedOCSPResponse",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				v.MaxResponseSize = 64

				cert = e.issue(t, withOCSP(e.ocsp.URL))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Good, nil))

				return cert, e.ca
			},
			err: ErrResponseTooLarge,
		},
		{
			name: "ShouldTimeoutHangingOCSPServer",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				v.Timeout = 100 * time.Millisecond
				e.ocsp.hang = true

				return e.issue(t, withOCSP(e.ocsp.URL)), e.ca
			},
			err: context.DeadlineExceeded,
		},
		{
			name: "ShouldUseOCSPWhenCRLCanNotBeAuthenticated",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL), withOCSP(e.ocsp.URL))
				e.crl.set(newCRL(t, e.attacker, e.attackerKey, nil))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Revoked, nil))

				return cert, e.ca
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldUseOCSPWhenNoDistributionPointCanBeUsed",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				second := newTestServer(t)

				e.crl.status = http.StatusNotFound

				cert = e.issue(t, withCRL(e.crl.URL, second.URL), withOCSP(e.ocsp.URL))
				second.set(newCRL(t, e.attacker, e.attackerKey, nil))
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Revoked, nil))

				return cert, e.ca
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldNotDetermineStatusWhenNoSourceCanBeAuthenticated",
			setup: func(t *testing.T, e *testEnv, v *Verifier) (cert, issuer *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL), withOCSP(e.ocsp.URL))
				e.crl.set(newCRL(t, e.attacker, e.attackerKey, nil))
				e.ocsp.set(newOCSPResponse(t, e.attacker, e.attacker, e.attackerKey, cert, ocsp.Good, nil))

				return cert, e.ca
			},
			err: ErrOCSPInvalid,
		},
	}

	for _, tc := range testCases {
		for _, hardFail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/HardFail=%t", tc.name, hardFail), func(t *testing.T) {
				t.Parallel()

				e := newTestEnv(t)
				v := &Verifier{HardFail: hardFail, Timeout: 5 * time.Second}

				cert, issuer := tc.setup(t, e, v)

				start := time.Now()

				revoked, ok, err := v.VerifyCertificate(context.Background(), cert, issuer)

				assert.Less(t, time.Since(start), 4*time.Second)
				assert.Equal(t, tc.ok, ok)

				if tc.ok {
					assert.Equal(t, tc.revoked, revoked)
					assert.NoError(t, err)
				} else {
					assert.Equal(t, hardFail, revoked)
					assert.ErrorIs(t, err, tc.err)
				}
			})
		}
	}
}

func TestVerifierVerifyCertificateContext(t *testing.T) {
	e := newTestEnv(t)
	e.crl.hang = true

	cert := e.issue(t, withCRL(e.crl.URL))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()

	revoked, ok, err := new(Verifier).VerifyCertificate(ctx, cert, e.ca)

	assert.Less(t, time.Since(start), 4*time.Second)
	assert.False(t, revoked)
	assert.False(t, ok)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestVerifierCRLCache(t *testing.T) {
	for _, hardFail := range []bool{false, true} {
		t.Run(fmt.Sprintf("HardFail=%t", hardFail), func(t *testing.T) {
			e := newTestEnv(t)
			v := &Verifier{HardFail: hardFail}

			first, second := e.issue(t, withCRL(e.crl.URL)), e.issue(t, withCRL(e.crl.URL))
			e.crl.set(newCRL(t, e.ca, e.caKey, nil, second.SerialNumber))

			revoked, ok, err := v.VerifyCertificate(context.Background(), first, e.ca)
			require.NoError(t, err)
			assert.True(t, ok)
			assert.False(t, revoked)

			revoked, ok, err = v.VerifyCertificate(context.Background(), second, e.ca)
			require.NoError(t, err)
			assert.True(t, ok)
			assert.True(t, revoked)
			assert.Equal(t, int64(1), e.crl.hits.Load())

			// The cached CRL was authenticated by another issuer, so it must be fetched and verified again.
			foreign, _ := newCertificate(t, e.attacker, e.attackerKey, withCRL(e.crl.URL))

			revoked, ok, err = v.VerifyCertificate(context.Background(), foreign, e.attacker)
			assert.ErrorIs(t, err, ErrCRLInvalid)
			assert.False(t, ok)
			assert.Equal(t, hardFail, revoked)
			assert.Equal(t, int64(2), e.crl.hits.Load())

			revoked, ok, err = v.VerifyCertificate(context.Background(), first, e.ca)
			require.NoError(t, err)
			assert.True(t, ok)
			assert.False(t, revoked)
			assert.Equal(t, int64(2), e.crl.hits.Load())
		})
	}
}

func TestCRLCacheExpiry(t *testing.T) {
	now := time.Now()

	cache := &crlCache{}

	current, expired, undated := crlKey{uri: "current"}, crlKey{uri: "expired"}, crlKey{uri: "undated"}

	cache.put(current, &x509.RevocationList{NextUpdate: now.Add(time.Hour)}, now)
	cache.put(expired, &x509.RevocationList{NextUpdate: now.Add(-time.Hour)}, now)
	cache.put(undated, &x509.RevocationList{}, now)

	assert.NotNil(t, cache.get(current, now))
	assert.Nil(t, cache.get(expired, now))
	assert.Nil(t, cache.get(undated, now))
	assert.Nil(t, cache.get(crlKey{uri: "current", issuer: [32]byte{1}}, now))

	assert.Nil(t, cache.get(current, now.Add(time.Hour)))
	assert.Empty(t, cache.entries)

	cache.put(current, &x509.RevocationList{NextUpdate: now.Add(time.Hour)}, now)
	cache.put(expired, &x509.RevocationList{NextUpdate: now.Add(3 * time.Hour)}, now.Add(2*time.Hour))
	assert.Len(t, cache.entries, 1)
}

func TestVerifierConcurrent(t *testing.T) {
	e := newTestEnv(t)
	v := &Verifier{}

	good, bad := e.issue(t, withCRL(e.crl.URL)), e.issue(t, withCRL(e.crl.URL))
	e.crl.set(newCRL(t, e.ca, e.caKey, nil, bad.SerialNumber))

	var wg sync.WaitGroup

	for i := range 32 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			cert := good
			if i%2 == 1 {
				cert = bad
			}

			revoked, ok, err := v.VerifyCertificate(context.Background(), cert, e.ca)

			assert.NoError(t, err)
			assert.True(t, ok)
			assert.Equal(t, i%2 == 1, revoked)
		}()
	}

	wg.Wait()
}

func TestVerifyCertificateWithIssuer(t *testing.T) {
	for _, hardFail := range []bool{false, true} {
		t.Run(fmt.Sprintf("HardFail=%t", hardFail), func(t *testing.T) {
			setGlobals(t, hardFail, http.DefaultClient)

			e := newTestEnv(t)

			cert := e.issue(t, withCRL(e.crl.URL))
			e.crl.set(newCRL(t, e.ca, e.caKey, nil, cert.SerialNumber))

			revoked, ok, err := VerifyCertificateWithIssuer(context.Background(), cert, e.ca)
			assert.NoError(t, err)
			assert.True(t, ok)
			assert.True(t, revoked)

			forged := e.issue(t, withCRL(e.ocsp.URL))
			e.ocsp.set(newCRL(t, e.attacker, e.attackerKey, nil))

			revoked, ok, err = VerifyCertificateWithIssuer(context.Background(), forged, e.ca)
			assert.ErrorIs(t, err, ErrCRLInvalid)
			assert.False(t, ok)
			assert.Equal(t, hardFail, revoked)
		})
	}
}

func TestVerifyCertificateError(t *testing.T) {
	testCases := []struct {
		name    string
		setup   func(t *testing.T, e *testEnv) (cert *x509.Certificate)
		client  *http.Client
		revoked bool
		ok      bool
		err     error
	}{
		{
			name: "ShouldPermitCertificateNotOnCRLOfDownloadedIssuer",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL), withIssuerURL(e.aia.URL))
				e.aia.set(e.ca.Raw)
				e.crl.set(newCRL(t, e.ca, e.caKey, nil))

				return cert
			},
			ok: true,
		},
		{
			name: "ShouldRejectCertificateOnCRLOfDownloadedPEMIssuer",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL), withIssuerURL(e.aia.URL))
				e.aia.set(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.ca.Raw}))
				e.crl.set(newCRL(t, e.ca, e.caKey, nil, cert.SerialNumber))

				return cert
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldRejectCertificateWithRevokedOCSPStatusOfDownloadedIssuer",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				cert = e.issue(t, withOCSP(e.ocsp.URL), withIssuerURL(e.aia.URL))
				e.aia.set(e.ca.Raw)
				e.ocsp.set(newOCSPResponse(t, e.ca, e.ca, e.caKey, cert, ocsp.Revoked, nil))

				return cert
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldRejectCertificateOnCRLOfDownloadedReissuedIssuerWithAnotherSubjectKeyID",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				issuer := reissueCA(t, e.ca, e.caKey)

				cert = e.issue(t, withCRL(e.crl.URL), withIssuerURL(e.aia.URL))
				e.aia.set(issuer.Raw)
				e.crl.set(newCRL(t, issuer, e.caKey, nil, cert.SerialNumber))

				return cert
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldNotTrustCRLForgedByDownloadedIssuer",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL), withIssuerURL(e.aia.URL))
				e.aia.set(e.attacker.Raw)
				e.crl.set(newCRL(t, e.attacker, e.attackerKey, nil))

				return cert
			},
			err: ErrIssuerMismatch,
		},
		{
			name: "ShouldNotTrustOCSPResponseForgedByDownloadedIssuer",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				cert = e.issue(t, withOCSP(e.ocsp.URL), withIssuerURL(e.aia.URL))
				e.aia.set(e.attacker.Raw)
				e.ocsp.set(newOCSPResponse(t, e.attacker, e.attacker, e.attackerKey, cert, ocsp.Good, nil))

				return cert
			},
			err: ErrIssuerMismatch,
		},
		{
			name: "ShouldNotDetermineStatusWithoutIssuerURL",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL))
				e.crl.set(newCRL(t, e.attacker, e.attackerKey, nil))

				return cert
			},
			err: ErrNoIssuer,
		},
		{
			name: "ShouldNotDetermineStatusWhenIssuerUnavailable",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				e.aia.status = http.StatusNotFound

				cert = e.issue(t, withCRL(e.crl.URL), withIssuerURL(e.aia.URL))
				e.crl.set([]byte("unsigned"))

				return cert
			},
			err: ErrNoIssuer,
		},
		{
			name: "ShouldRejectOversizedIssuer",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				cert = e.issue(t, withCRL(e.crl.URL), withIssuerURL(e.aia.URL))
				e.aia.set(make([]byte, DefaultMaxResponseSize+1))
				e.crl.set(newCRL(t, e.ca, e.caKey, nil))

				return cert
			},
			err: ErrResponseTooLarge,
		},
		{
			name: "ShouldTimeoutHangingIssuerServer",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				e.aia.hang = true

				return e.issue(t, withCRL(e.crl.URL), withIssuerURL(e.aia.URL))
			},
			client: &http.Client{Timeout: 100 * time.Millisecond},
			err:    ErrNoIssuer,
		},
		{
			name: "ShouldTimeoutHangingCRLServer",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				e.crl.hang = true

				cert = e.issue(t, withCRL(e.crl.URL), withIssuerURL(e.aia.URL))
				e.aia.set(e.ca.Raw)

				return cert
			},
			client: &http.Client{Timeout: 100 * time.Millisecond},
			err:    ErrFailedGetCRL,
		},
		{
			name: "ShouldUseSelfSignedCertificateAsIssuer",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				cert, key := newCA(t, "Root CA", withCRL(e.crl.URL))
				e.crl.set(newCRL(t, cert, key, nil, cert.SerialNumber))

				return cert
			},
			revoked: true,
			ok:      true,
		},
		{
			name: "ShouldPermitCertificateWithoutRevocationSources",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				return e.issue(t)
			},
			ok: true,
		},
		{
			name: "ShouldRejectExpiredCertificate",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				return e.issue(t, func(template *x509.Certificate) {
					template.NotAfter = time.Now().Add(-time.Minute)
				})
			},
			revoked: true,
			ok:      true,
			err:     ErrCertificateExpired,
		},
		{
			name: "ShouldRejectCertificateNotYetValid",
			setup: func(t *testing.T, e *testEnv) (cert *x509.Certificate) {
				return e.issue(t, func(template *x509.Certificate) {
					template.NotBefore = time.Now().Add(time.Minute)
				})
			},
			revoked: true,
			ok:      true,
			err:     ErrCertificateNotYetValid,
		},
	}

	for _, tc := range testCases {
		for _, hardFail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/HardFail=%t", tc.name, hardFail), func(t *testing.T) {
				client := tc.client
				if client == nil {
					client = http.DefaultClient
				}

				setGlobals(t, hardFail, client)

				e := newTestEnv(t)

				cert := tc.setup(t, e)

				start := time.Now()

				revoked, ok, err := VerifyCertificateError(cert)

				assert.Less(t, time.Since(start), 4*time.Second)
				assert.Equal(t, tc.ok, ok)

				if tc.ok {
					assert.Equal(t, tc.revoked, revoked)
				} else {
					assert.Equal(t, hardFail, revoked)
				}

				if tc.err == nil {
					assert.NoError(t, err)
				} else {
					require.ErrorIs(t, err, tc.err)
					assert.False(t, strings.HasSuffix(err.Error(), "\n"))
					assert.True(t, strings.HasPrefix(err.Error(), strings.ToLower(err.Error()[:1])))
				}

				r, o := VerifyCertificate(cert)

				assert.Equal(t, revoked, r)
				assert.Equal(t, ok, o)
			})
		}
	}
}

func TestDefaults(t *testing.T) {
	c := newChecker(nil, false, &crlCache{})

	assert.Equal(t, http.DefaultClient, c.client)
	assert.Equal(t, DefaultTimeout, c.timeout)
	assert.Equal(t, DefaultMaxCRLSize, c.maxCRL)
	assert.Equal(t, DefaultMaxResponseSize, c.maxResponse)
	assert.Equal(t, DefaultMaxOCSPAge, c.maxOCSPAge)
}

func TestErrorUnwrap(t *testing.T) {
	inner := errors.New("inner")

	assert.ErrorIs(t, WrapError(CertificateError, ParseFailed, inner), inner)
	assert.NoError(t, errors.Unwrap(NewError(CertificateError, ParseFailed)))
}

type testEnv struct {
	ca, attacker       *x509.Certificate
	caKey, attackerKey *ecdsa.PrivateKey
	crl, ocsp, aia     *testServer
}

type testServer struct {
	*httptest.Server

	mu      sync.Mutex
	body    []byte
	status  int
	hang    bool
	chunked bool
	delay   time.Duration
	hits    atomic.Int64
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	e := &testEnv{crl: newTestServer(t), ocsp: newTestServer(t), aia: newTestServer(t)}

	// The attacker shares the subject of the real issuer, and differs only by key.
	e.ca, e.caKey = newCA(t, "Test CA")
	e.attacker, e.attackerKey = newCA(t, "Test CA")

	return e
}

func (e *testEnv) issue(t *testing.T, opts ...func(template *x509.Certificate)) *x509.Certificate {
	t.Helper()

	cert, _ := newCertificate(t, e.ca, e.caKey, opts...)

	return cert
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	s := &testServer{status: http.StatusOK}
	done := make(chan struct{})

	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)

		if s.hang {
			select {
			case <-done:
			case <-r.Context().Done():
			}

			return
		}

		if s.delay > 0 {
			select {
			case <-time.After(s.delay):
			case <-done:
			case <-r.Context().Done():
			}
		}

		s.mu.Lock()
		body := s.body
		s.mu.Unlock()

		w.WriteHeader(s.status)

		if s.chunked {
			w.(http.Flusher).Flush()
		}

		_, _ = w.Write(body)
	}))

	t.Cleanup(func() {
		close(done)
		s.Close()
	})

	return s
}

func (s *testServer) set(body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.body = body
}

func setGlobals(t *testing.T, hardFail bool, client *http.Client) {
	t.Helper()

	prevHardFail, prevClient := HardFail, HTTPClient

	HardFail, HTTPClient = hardFail, client

	t.Cleanup(func() {
		HardFail, HTTPClient = prevHardFail, prevClient
	})
}

func withCRL(uris ...string) func(template *x509.Certificate) {
	return func(template *x509.Certificate) {
		template.CRLDistributionPoints = uris
	}
}

func withOCSP(uris ...string) func(template *x509.Certificate) {
	return func(template *x509.Certificate) {
		template.OCSPServer = uris
	}
}

func withIssuerURL(uris ...string) func(template *x509.Certificate) {
	return func(template *x509.Certificate) {
		template.IssuingCertificateURL = uris
	}
}

func withOCSPSigning(template *x509.Certificate) {
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
}

func withCA(template *x509.Certificate) {
	template.IsCA = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
}

func withRawScope(value []byte) func(template *x509.RevocationList) {
	return func(template *x509.RevocationList) {
		template.ExtraExtensions = []pkix.Extension{{Id: oidExtensionIssuingDistributionPoint, Critical: true, Value: value}}
	}
}

func withScope(t *testing.T, idp issuingDistributionPoint) func(template *x509.RevocationList) {
	t.Helper()

	value, err := asn1.Marshal(idp)
	require.NoError(t, err)

	return func(template *x509.RevocationList) {
		template.ExtraExtensions = []pkix.Extension{{Id: oidExtensionIssuingDistributionPoint, Critical: true, Value: value}}
	}
}

var keyCompromiseOnly = asn1.BitString{Bytes: []byte{0x40}, BitLength: 2}

func uriName(uri string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)}
}

var testSerial atomic.Int64

func newSerial() *big.Int {
	return big.NewInt(testSerial.Add(1) + 1000)
}

func newCA(t *testing.T, name string, opts ...func(template *x509.Certificate)) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	opts = append([]func(template *x509.Certificate){func(template *x509.Certificate) {
		template.Subject = pkix.Name{CommonName: name}
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}}, opts...)

	return newCertificate(t, nil, nil, opts...)
}

func newCertificate(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, opts ...func(template *x509.Certificate)) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial := newSerial()

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: fmt.Sprintf("Certificate %s", serial)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	for _, opt := range opts {
		opt(template)
	}

	if issuer == nil {
		issuer, issuerKey = template, key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert, key
}

func reissueCA(t *testing.T, ca *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          newSerial(),
		RawSubject:            ca.RawSubject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{0x01, 0x02, 0x03, 0x04},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

func newCRL(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, opt func(template *x509.RevocationList), revoked ...*big.Int) []byte {
	t.Helper()

	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
	}

	for _, serial := range revoked {
		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Hour),
		})
	}

	if opt != nil {
		opt(template)
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, issuer, issuerKey)
	require.NoError(t, err)

	return der
}

func newUndatedCRL(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	algorithm := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}

	tbs, err := asn1.Marshal(struct {
		Version    int
		Signature  pkix.AlgorithmIdentifier
		Issuer     asn1.RawValue
		ThisUpdate time.Time
	}{1, algorithm, asn1.RawValue{FullBytes: issuer.RawSubject}, time.Now().Add(-time.Hour).UTC()})
	require.NoError(t, err)

	digest := sha256.Sum256(tbs)

	signature, err := ecdsa.SignASN1(rand.Reader, issuerKey, digest[:])
	require.NoError(t, err)

	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, algorithm, asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}})
	require.NoError(t, err)

	return der
}

func newOCSPResponse(t *testing.T, issuer, responder *x509.Certificate, responderKey *ecdsa.PrivateKey, cert *x509.Certificate, status int, opt func(template *ocsp.Response)) []byte {
	t.Helper()

	template := ocsp.Response{
		Status:       status,
		SerialNumber: cert.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Hour),
		NextUpdate:   time.Now().Add(time.Hour),
		IssuerHash:   crypto.SHA1,
	}

	if status == ocsp.Revoked {
		template.RevokedAt = time.Now().Add(-time.Hour)
		template.RevocationReason = ocsp.KeyCompromise
	}

	if responder != issuer {
		template.Certificate = responder
	}

	if opt != nil {
		opt(&template)
	}

	der, err := ocsp.CreateResponse(issuer, responder, template, responderKey)
	require.NoError(t, err)

	return der
}
