package sctdemo

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"html"
	"net"
	"net/http"
	"strings"
	"time"

	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/loglist"
)

type Server struct {
	HTTPClient     *http.Client
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

	host := strings.Split(hello.ServerName, ".")[0]
	for _, token := range strings.Split(host, "-") {
		if token == "" {
			continue
		}
		ctlog, err := s.GetLog(ctx, token)
		if err != nil {
			return nil, err
		}
		sct, err := s.GetCachedSCT(ctx, fingerprint, ctlog.LogID)
		if err != nil {
			return nil, err
		}
		if sct == nil {
			sct, err = addChain(ctx, s.HTTPClient, ctlog, cert.Certificate)
			if err != nil {
				return nil, err
			}
			if err := s.CacheSCT(ctx, fingerprint, ctlog.LogID, sct); err != nil {
				return nil, err
			}
		}
		newCert.SignedCertificateTimestamps = append(newCert.SignedCertificateTimestamps, sct)
	}

	return newCert, nil
}

func (s *Server) Serve(l net.Listener) error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		host := strings.Split(strings.Split(r.Host, ":")[0], ".")[0]
		var logs []*loglist.Log
		for _, token := range strings.Split(host, "-") {
			if token == "" {
				continue
			}
			ctlog, err := s.GetLog(ctx, token)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			logs = append(logs, ctlog)
		}
		fmt.Fprint(w, "<html><body>This TLS handshake includes SCTs from:<ul>")
		for _, log := range logs {
			fmt.Fprintf(w, "<li>%s</li>", html.EscapeString(log.Description))
		}
		fmt.Fprint(w, "</ul></body></html>")
	})

	hs := &http.Server{
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return hs.Serve(tls.NewListener(l, &tls.Config{
		GetCertificate: s.GetCertificateWithSCTs,
	}))
}
