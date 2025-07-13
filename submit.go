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
