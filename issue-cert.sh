#!/usr/bin/env bash
set -euo pipefail
umask 077

DEFAULT_CA_DIR="$HOME/local-ca"

read -r -p "Path to your CA folder [$DEFAULT_CA_DIR]: " CA_DIR
CA_DIR="${CA_DIR:-$DEFAULT_CA_DIR}"

# Expand a leading ~/ if the user typed one.
case "$CA_DIR" in
  "~")   CA_DIR="$HOME" ;;
  "~/"*) CA_DIR="$HOME/${CA_DIR#~/}" ;;
esac

if [[ ! -f "$CA_DIR/openssl.cnf" ||
      ! -f "$CA_DIR/certs/ca.crt" ||
      ! -f "$CA_DIR/private/ca.key" ]]; then
  echo "Error: I couldn't find the CA config, certificate, and private key in: $CA_DIR" >&2
  exit 1
fi

CA_DIR="$(cd "$CA_DIR" && pwd -P)"

read -r -p "DNS hostname for the certificate (e.g. localhost or app.example.test): " HOST

# Accept DNS names, including localhost, but not IP addresses or config-file syntax.
HOST_RE='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$'
if [[ ! "$HOST" =~ $HOST_RE ]]; then
  echo "Error: enter a valid DNS hostname, not an IP address." >&2
  exit 1
fi

DEFAULT_OUT_DIR="$PWD/${HOST}-ssl"

while true; do
  read -r -p "Folder for the SSL files [$DEFAULT_OUT_DIR]: " OUT_DIR
  OUT_DIR="${OUT_DIR:-$DEFAULT_OUT_DIR}"

  if [[ -e "$OUT_DIR" && ! -d "$OUT_DIR" ]]; then
    echo "That path is a file. Choose a different folder." >&2
  elif [[ -d "$OUT_DIR" ]] &&
       [[ -n "$(find "$OUT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "That folder is not empty. Choose a different folder." >&2
  else
    break
  fi
done

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd -P)"
chmod 700 "$OUT_DIR"

KEY="$OUT_DIR/server.key"
CSR="$OUT_DIR/server.csr"
CERT="$OUT_DIR/server.crt"
CA_CERT="$OUT_DIR/ca.crt"
CHAIN="$OUT_DIR/server-chain.pem"
EXT_FILE="$OUT_DIR/server-ext.cnf"

# This server key is unencrypted so a web server can start without a prompt.
# File permissions are restricted; protect this file.
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -out "$KEY"

openssl req -new \
  -key "$KEY" \
  -out "$CSR" \
  -subj "/CN=$HOST"

cat > "$EXT_FILE" <<EOF
[ server_cert ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ alt_names ]
DNS.1 = $HOST
EOF

# The CA config uses relative paths, so run the signing command from its folder.
(
  cd "$CA_DIR"
  openssl ca -batch \
    -config openssl.cnf \
    -extfile "$EXT_FILE" \
    -extensions server_cert \
    -days 365 \
    -notext \
    -md sha256 \
    -in "$CSR" \
    -out "$CERT"
)

cp "$CA_DIR/certs/ca.crt" "$CA_CERT"
cat "$CERT" "$CA_CERT" > "$CHAIN"

chmod 600 "$KEY"
chmod 644 "$CSR" "$CERT" "$CA_CERT" "$CHAIN" "$EXT_FILE"

openssl verify \
  -CAfile "$CA_CERT" \
  -purpose sslserver \
  -verify_hostname "$HOST" \
  "$CERT"

echo
echo "Created in:        $OUT_DIR"
echo "Private key:       $KEY"
echo "Certificate:       $CERT"
echo "CSR:               $CSR"
echo "CA certificate:    $CA_CERT"
echo "Combined chain:    $CHAIN"
echo
openssl x509 -in "$CERT" -noout -subject -issuer -dates
