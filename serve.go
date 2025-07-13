package sctdemo

import (
	"context"
	"crypto/tls"
	"crypto/sha256"

	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/loglist"
)

type Server struct {
	GetCertificate func(context.Context, *tls.ClientHelloInfo) (*tls.Certificate, error)
	GetLog         func(context.Context, string) (*loglist.Log, error)
	CacheSCT       func(context.Context, [32]byte, cttypes.LogID, []byte) error
	GetCachedSCT   func(context.Context, [32]byte, cttypes.LogID) ([]byte, error)
}

func (s *Server) GetCertificateWithSCTs(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	ctx := hello.Context()
	cert, err := s.GetCertificate(ctx, hello)
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(cert.Certificate[0])
	newCert := new(tls.Certificate)
	*newCert = *cert

	// TODO: take the first component of hello.ServerName and split it on hyphens. Each token represents a log name.  For each log name, pass it to GetLog to get the log. Then obtain an SCT for it, first by checking the cache (by passing fingerprint and the log ID to GetCachedSCT). If that returns nil, then submit the certificate chain (cert.Certificate) using addChain() and then cache the result by calling CacheSCT.  Append the SCT to newCert.SignedCertificateTimestamps

	return newCert, nil
}

func (s *Server) Serve(l net.Listener) error {
	// TODO: add a handler that looks at the first component of server name, splits it, calls GetLog on each token (just like GetCertificateWithSCTs) and then return a simple page saying "This TLS handshake includes SCTs from:" followed by a list of log descriptions
	hs := &http.Server{
		ReadTimeout: 10*time.Second,
		WriteTimeout: 10*time.Second,
	}
	return hs.Serve(tls.NewListener(l, &tls.Config{
		GetCertificate: s.GetCertificateWithSCTs,
	}))
}
