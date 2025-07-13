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

package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"src.agwa.name/go-listener"
	listenercert "src.agwa.name/go-listener/cert"

	"software.sslmate.com/src/certspotter/ctclient"
	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/loglist"
	"software.sslmate.com/src/sctdemo"
)

func main() {
	certFile := flag.String("cert", "", "path to PEM file containing wildcard certificate, chain, and private key")
	logListFile := flag.String("loglist", "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json", "path or HTTPS URL to JSON log list")
	listenerSpec := flag.String("listen", "", "where to listen, in go-listener syntax (https://pkg.go.dev/src.agwa.name/go-listener#readme-listener-syntax)")
	flag.Parse()

	if *certFile == "" || *logListFile == "" || *listenerSpec == "" {
		flag.Usage()
		os.Exit(1)
	}

	list, err := loglist.Load(context.Background(), *logListFile)
	if err != nil {
		log.Fatalf("error loading log list: %v", err)
	}

	srv := &sctdemo.Server{HTTPClient: ctclient.NewHTTPClient(nil)}

	certFunc := listenercert.GetCertificateFromFile(*certFile)
	srv.GetCertificate = func(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certFunc(hello)
	}

	srv.GetLog = func(ctx context.Context, prefix string) (*loglist.Log, error) {
		var match *loglist.Log
		for _, l := range list.AllLogs() {
			hexid := hex.EncodeToString(l.LogID[:])
			if strings.HasPrefix(hexid, strings.ToLower(prefix)) {
				if match != nil {
					return nil, fmt.Errorf("log prefix %q is ambiguous", prefix)
				}
				match = l
			}
		}
		if match == nil {
			return nil, fmt.Errorf("no log with prefix %q", prefix)
		}
		return match, nil
	}

	cache := struct {
		mu   sync.Mutex
		data map[[32]byte]map[cttypes.LogID][]byte
	}{data: make(map[[32]byte]map[cttypes.LogID][]byte)}

	srv.CacheSCT = func(ctx context.Context, fp [32]byte, id cttypes.LogID, sct []byte) error {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		m, ok := cache.data[fp]
		if !ok {
			m = make(map[cttypes.LogID][]byte)
			cache.data[fp] = m
		}
		cp := make([]byte, len(sct))
		copy(cp, sct)
		m[id] = cp
		return nil
	}

	srv.GetCachedSCT = func(ctx context.Context, fp [32]byte, id cttypes.LogID) ([]byte, error) {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		m, ok := cache.data[fp]
		if !ok {
			return nil, nil
		}
		sct, ok := m[id]
		if !ok {
			return nil, nil
		}
		cp := make([]byte, len(sct))
		copy(cp, sct)
		return cp, nil
	}

	l, err := listener.Open(*listenerSpec)
	if err != nil {
		log.Fatalf("error opening listener: %v", err)
	}
	defer l.Close()

	if err := srv.Serve(l); err != nil {
		log.Fatal(err)
	}
}
