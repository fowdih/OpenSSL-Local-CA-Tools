# OpenSSL Local CA Tools

Interactive Bash scripts for creating a private root Certificate Authority (CA)
and issuing a TLS server certificate with OpenSSL.

These scripts are intended for local development, labs, and private networks.
They do not create certificates trusted by public browsers or operating systems
automatically.

## Features

- Creates a self-signed root CA.
- Protects the CA private key with a passphrase.
- Creates a server private key, CSR, and CA-signed certificate.
- Adds DNS names and IP addresses to the certificate's Subject Alternative Name
  (SAN) extension.
- Automatically includes `localhost`, `127.0.0.1`, and `::1`.
- Sets issued server certificates to expire after 365 days.

## Requirements

- Linux
- Bash
- OpenSSL
- Python 3 (used by `issue-cert.sh` to validate DNS names and IP addresses)

## Scripts

- `create-ca.sh` — creates the CA files in a folder you choose. The root CA
  certificate is valid for 10 years.
- `issue-cert.sh` — creates a server key and CSR, signs the certificate with
  your CA, and asks for the DNS names or IP addresses to include.

## Usage

Make the scripts executable:

```bash
chmod +x create-ca.sh issue-cert.sh
