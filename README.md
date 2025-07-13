# SCT Demo Server

**sctdemo** is an HTTPS server that attaches SCTs to the TLS handshake from the logs specified in the server name. The first component of the server name is interpreted as a hyphen-separated list of log identifiers. When sctdemo handles a TLS connection, it obtains SCTs for its certificate from the specified logs, and sends them to the client in the TLS handshake. This can be used for testing CT policy enforcement in clients.

## Public Instance

SSLMate hosts a public instance of sctdemo under **sct-demo.sslmate.net**. This instance uses SSLMate Log IDs as the log identifier, which can be found in the ID column at <https://sslmate.com/app/ctlogs>. The instance's certificate expires on **2026-08-11**, which means it only works with logs which accept this expiration date.

### Examples

SCTs from Google Argon 2026h2 only (this should fail in CT-enforcing user agents): https://26900004.sct-demo.sslmate.net

SCTs from Google Argon 2026h2 and Let's Encrypt Oak 2026h2: https://26900004-26900006.sct-demo.sslmate.net

## Running It Yourself

**sctdemod** is a standalone daemon you can run yourself.

To install, run:

```
go install software.sslmate.com/src/sctdemo/cmd/sctdemod@latest
```

You need a wildcard certificate without embedded SCTs. You can obtain such a certificate from Amazon.

To run sctdemod on port 443 with the certificate, run:

```
sctdemod -cert /path/to/cert_chain_and_key.pem -listen tcp:443
```

sctdemod uses a hex-encoded log ID prefix as the log identifier.  For example, `0d1dbc89-dddcca34-ef9d0442.example.com` would serve a TLS handshake with SCTs from Sectigo Elephant 2025h2, Google Xenon 2025h2, and Geomys Tuscolo 2025h2.

### Usage

```
Usage of sctdemod:
  -cert string
        path to PEM file containing wildcard certificate, chain, and private key
  -listen string
        where to listen, in go-listener syntax (https://pkg.go.dev/src.agwa.name/go-listener#readme-listener-syntax)
  -loglist string
        path or HTTPS URL to JSON log list (default "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json")
```
