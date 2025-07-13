// Copyright (C) 2025 Opsmate, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the
// sale, use or other dealings in this Software without prior written
// authorization.

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
	// HTTPClient is used for submitting certificates to logs
	HTTPClient *http.Client

	// GetCertificate returns the certificate (without SCTs) to present to the client
	GetCertificate func(context.Context, *tls.ClientHelloInfo) (*tls.Certificate, error)

	// GetLog looks up a log by the identifier that was presented in the server name
	GetLog func(context.Context, string) (*loglist.Log, error)

	// Cache an SCT for the given certificate fingerprint from the given log
	CacheSCT func(context.Context, [32]byte, cttypes.LogID, []byte) error

	// Return a cached SCT (or nil if not cached) for the given certificate fingerprint from the given log
	GetCachedSCT func(context.Context, [32]byte, cttypes.LogID) ([]byte, error)
}

func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
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

// Serve accepts and serves HTTPS connections on l
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
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: s.getCertificate,
	}))
}
