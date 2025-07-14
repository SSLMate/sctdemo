# SCT Demo Server

* https://none.sct-demo.sslmate.net serves **no SCTs** (in the certificate, OCSP response, or TLS extension) (this should fail in CT-enforcing user agents)

* https://26900004.sct-demo.sslmate.net serves SCTs from **Google Argon 2026h2** in the TLS extension (this should fail in CT-enforcing user agents)

* https://26900004-26900006.sct-demo.sslmate.net serves SCTs from **Google Argon 2026h2** and **Let's Encrypt Oak 2026h2** in the TLS extension

* https://26900004-26900006-26900015.sct-demo.sslmate.net serves SCTs from **Google Argon 2026h2**, **Let's Encrypt Oak 2026h2**, and **Sectigo Elephant 2026h2** in the TLS extension

The first component of the server name is a hyphen-separated list of numeric log identifiers. When the SCT demo server handles a TLS connection, it obtains SCTs for its certificate (which has no embedded SCTs) from the specified logs, and sends them to the client in the TLS handshake extension. This can be used for testing CT policy enforcement in clients.

For a list of numeric log identifiers, see the ID column of <https://sslmate.com/app/ctlogs>.  Note that you can only use logs which will accept a trusted TLS certificate expiring on **2026-08-11**; other logs will refuse to accept the demo server's certificate.

## Running It Yourself

**sctdemod** is a standalone daemon you can run yourself.

To install, run:

```
go install software.sslmate.com/src/sctdemo/cmd/sctdemod@latest
```

You need a wildcard certificate without embedded SCTs, which you can obtain from Amazon Web Services.

To run sctdemod on port 443 with the certificate, run:

```
sctdemod -cert /path/to/cert_chain_and_key.pem -listen tcp:443
```

Unlike the public instance, sctdemod uses a hex-encoded [key ID](https://www.rfc-editor.org/rfc/rfc6962#section-3.2) prefix as the log identifier.  For example, `0d1dbc89-dddcca34-ef9d0442.example.com` would serve SCTs from Sectigo Elephant 2025h2, Google Xenon 2025h2, and Geomys Tuscolo 2025h2. The prefix can be any length as long as it unambiguously identifies a log.

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
