#!/usr/bin/env bash
set -euo pipefail
umask 077

CA_DIR="${1:-$HOME/local-ca}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: OpenSSL is not installed or not in PATH." >&2
  exit 1
fi

if [[ -d "$CA_DIR" ]] && [[ -n "$(find "$CA_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "Error: $CA_DIR exists and is not empty; refusing to overwrite it." >&2
  exit 1
fi

mkdir -p "$CA_DIR"/{certs,crl,newcerts,private}
CA_DIR="$(cd "$CA_DIR" && pwd -P)"
chmod 700 "$CA_DIR" "$CA_DIR/private"

: > "$CA_DIR/index.txt"
printf '1000\n' > "$CA_DIR/serial"
printf '1000\n' > "$CA_DIR/crlnumber"

cat > "$CA_DIR/openssl.cnf" <<'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
database          = $dir/index.txt
new_certs_dir     = $dir/newcerts
certificate       = $dir/certs/ca.crt
serial            = $dir/serial
crlnumber         = $dir/crlnumber
private_key       = $dir/private/ca.key
default_md        = sha256
default_days      = 825
default_crl_days  = 30
policy            = policy_loose
unique_subject    = no
copy_extensions   = none

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
prompt             = no
distinguished_name = req_distinguished_name
x509_extensions    = v3_ca
default_md         = sha256

[ req_distinguished_name ]
CN = Local Development Root CA

[ v3_ca ]
basicConstraints       = critical, CA:true
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
EOF

openssl genpkey \
  -algorithm RSA \
  -aes-256-cbc \
  -pkeyopt rsa_keygen_bits:4096 \
  -out "$CA_DIR/private/ca.key"

openssl req -new -x509 \
  -key "$CA_DIR/private/ca.key" \
  -sha256 \
  -days 3650 \
  -config "$CA_DIR/openssl.cnf" \
  -extensions v3_ca \
  -out "$CA_DIR/certs/ca.crt"

chmod 600 "$CA_DIR/private/ca.key"
chmod 644 "$CA_DIR/certs/ca.crt"

echo
echo "CA created in: $CA_DIR"
echo "Certificate:   $CA_DIR/certs/ca.crt"
echo "Private key:   $CA_DIR/private/ca.key"
echo
openssl x509 -in "$CA_DIR/certs/ca.crt" -noout -subject -dates -fingerprint -sha256
