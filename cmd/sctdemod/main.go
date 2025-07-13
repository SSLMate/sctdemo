package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strings"
	"sync"

	"src.agwa.name/go-listener"
	listenercert "src.agwa.name/go-listener/cert"

	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/loglist"
	"software.sslmate.com/src/sctdemo"
)

func main() {
	certFile := flag.String("cert", "", "path to certificate file")
	logListFile := flag.String("loglist", "", "path to log list JSON")
	listenerSpec := flag.String("listen", "", "listener specification")
	flag.Parse()

	if *certFile == "" || *logListFile == "" || *listenerSpec == "" {
		flag.Usage()
		return
	}

	list, err := loglist.ReadFile(*logListFile)
	if err != nil {
		log.Fatalf("error loading log list: %v", err)
	}

	srv := &sctdemo.Server{}

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
