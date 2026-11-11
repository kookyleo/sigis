#!/bin/sh
# Generates self-signed certificates that exercise the signature algorithm
# dispatch in sigis-hanko. Private keys are written to a temporary directory
# and deleted; only certificates are kept. Requires the openssl CLI (3.x).
set -eu
out=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mk() { # name keyalg-args digest-args...
  name=$1; shift
  openssl req -x509 -new -days 3650 -subj "/CN=sigis-hanko $name" \
    -keyout "$tmp/$name.key" -nodes -out "$out/$name.cert.pem" "$@" 2>/dev/null
}
mk ec-p256-sha256 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256
mk ec-p256-sha384 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha384
mk ec-p384-sha384 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -sha384
mk ec-p521-sha512 -newkey ec -pkeyopt ec_paramgen_curve:P-521 -sha512
mk rsa-sha256 -newkey rsa:2048 -sha256
mk rsa-pss-sha256 -newkey rsa:2048 -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32
mk rsa-pss-sha512-salt20 -newkey rsa:2048 -sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:20 -sigopt rsa_mgf1_md:sha512
mk ed25519 -newkey ed25519
