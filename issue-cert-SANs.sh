#!/usr/bin/env bash
set -euo pipefail
umask 077

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: OpenSSL is not installed or not in PATH." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: Python 3 is required to validate DNS names and IP addresses." >&2
  exit 1
fi

DEFAULT_CA_DIR="$HOME/local-ca"
read -r -p "Path to your CA folder [$DEFAULT_CA_DIR]: " CA_DIR
CA_DIR="${CA_DIR:-$DEFAULT_CA_DIR}"

case "$CA_DIR" in
  "~")   CA_DIR="$HOME" ;;
  "~/"*) CA_DIR="$HOME/${CA_DIR#~/}" ;;
esac

if [[ ! -f "$CA_DIR/openssl.cnf" ||
      ! -f "$CA_DIR/certs/ca.crt" ||
      ! -f "$CA_DIR/private/ca.key" ]]; then
  echo "Error: CA config, certificate, or private key not found in: $CA_DIR" >&2
  exit 1
fi
CA_DIR="$(cd "$CA_DIR" && pwd -P)"

read -r -p "Primary DNS name or IP address: " PRIMARY
if [[ -z "$PRIMARY" ]]; then
  echo "Error: a primary DNS name or IP address is required." >&2
  exit 1
fi

read -r -p "Additional DNS names or IPs, comma-separated (blank for none): " EXTRA_NAMES

DEFAULT_OUT_DIR="$PWD/server-ssl"

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

# Validate names and build the OpenSSL SAN extensions.
PRIMARY_INFO="$(
  python3 - "$PRIMARY" "$EXTRA_NAMES" "$EXT_FILE" <<'PY'
import ipaddress
import re
import sys

primary, extra, ext_path = sys.argv[1:4]

def classify(value):
    value = value.strip()
    if not value:
        return None

    if "%" in value:
        raise ValueError(f"Invalid IP address: {value}")

    try:
        return ("IP", str(ipaddress.ip_address(value)))
    except ValueError:
        pass

    if len(value) > 253:
        raise ValueError(f"Invalid DNS name: {value}")

    labels = value.split(".")
    label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    if not all(label_re.fullmatch(label) for label in labels):
        raise ValueError(f"Invalid DNS name or IP address: {value}")

    return ("DNS", value.lower())

try:
    primary_item = classify(primary)
    if primary_item is None:
        raise ValueError("A primary DNS name or IP address is required.")

    items = [primary_item]
    for value in extra.split(","):
        item = classify(value)
        if item is not None:
            items.append(item)

    # Always cover localhost and its IPv4/IPv6 loopback addresses.
    items.extend([
        ("DNS", "localhost"),
        ("IP", "127.0.0.1"),
        ("IP", "::1"),
    ])

    # Remove duplicates while preserving order.
    unique = []
    seen = set()
    for kind, value in items:
        key = (kind, value.lower() if kind == "DNS" else value)
        if key not in seen:
            seen.add(key)
            unique.append((kind, value))

    dns_names = [value for kind, value in unique if kind == "DNS"]
    ip_addresses = [value for kind, value in unique if kind == "IP"]

    with open(ext_path, "w", encoding="ascii") as f:
        f.write(
            "[ server_cert ]\n"
            "basicConstraints = critical, CA:FALSE\n"
            "keyUsage = critical, digitalSignature, keyEncipherment\n"
            "extendedKeyUsage = serverAuth\n"
            "subjectAltName = @alt_names\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid,issuer\n\n"
            "[ alt_names ]\n"
        )
        for i, name in enumerate(dns_names, 1):
            f.write(f"DNS.{i} = {name}\n")
        for i, address in enumerate(ip_addresses, 1):
            f.write(f"IP.{i} = {address}\n")

    print(f"{primary_item[0]}\t{primary_item[1]}")
except ValueError as exc:
    print(f"Error: {exc}", file=sys.stderr)
    sys.exit(1)
PY
)"

PRIMARY_TYPE="${PRIMARY_INFO%%$'\t'*}"
COMMON_NAME="${PRIMARY_INFO#*$'\t'}"

echo "Creating the server private key."
# Unencrypted so a server can start without a passphrase prompt; permissions are restricted.
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -out "$KEY"

openssl req -new \
  -key "$KEY" \
  -out "$CSR" \
  -subj "/CN=$COMMON_NAME"

# The CA config uses relative paths, so sign from inside the CA folder.
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

if [[ "$PRIMARY_TYPE" == "IP" ]]; then
  openssl verify -CAfile "$CA_CERT" -purpose sslserver \
    -verify_ip "$COMMON_NAME" "$CERT"
else
  openssl verify -CAfile "$CA_CERT" -purpose sslserver \
    -verify_hostname "$COMMON_NAME" "$CERT"
fi

echo
echo "Created in:       $OUT_DIR"
echo "Private key:      $KEY"
echo "Certificate:      $CERT"
echo "CSR:              $CSR"
echo "CA certificate:   $CA_CERT"
echo "Combined chain:   $CHAIN"
echo "Certificate SANs include localhost, 127.0.0.1, and ::1."
openssl x509 -in "$CERT" -noout -subject -issuer -dates -ext subjectAltName
