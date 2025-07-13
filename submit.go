package sctdemo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"software.sslmate.com/src/certspotter/ctcrypto"
	"software.sslmate.com/src/certspotter/cttypes"
	"software.sslmate.com/src/certspotter/loglist"
)

func addChain(ctx context.Context, httpClient *http.Client, ctlog *loglist.Log, chain [][]byte) ([]byte, error) {
	fullURL, err := url.JoinPath(ctlog.GetSubmissionURL(), "/ct/v1/add-chain")
	if err != nil {
		return nil, err
	}

	requestBody, err := json.Marshal(struct {
		Chain [][]byte `json:"chain"`
	}{
		Chain: chain,
	})
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "sctdemo")
	request.Header.Set("Content-Type", "application/json")

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	responseBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("Post %q: error reading response: %w", fullURL, err)
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("Post %q: %s (%q)", fullURL, response.Status, string(responseBody))
	}

	sct := new(cttypes.SignedCertificateTimestamp)
	if err := json.Unmarshal(responseBody, sct); err != nil {
		return nil, fmt.Errorf("error unmarshaling response from %q: %w", fullURL, err)
	}

	if err := ctcrypto.PublicKey(ctlog.Key).Verify(ctcrypto.SignatureInputForCertSCT(sct, chain[0]), sct.Signature); err != nil {
		return nil, fmt.Errorf("error verifying SCT signature from %q: %w", fullURL, err)
	}

	return sct.Bytes()
}
