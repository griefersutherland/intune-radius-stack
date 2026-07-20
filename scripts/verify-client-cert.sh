#!/bin/sh
# freeradius-wifi-eap-tls - client certificate identity/EKU/CRL verify hook, calls the compliance helper
# Copyright (C) 2026  griefersutherland
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

CERT="$1"
RADIUS_USERNAME="${2:-}"
CALLING_STATION_ID="${3:-}"

LOG="/logs/radius-verify.log"
HELPER_URL="${HELPER_URL:-http://intune-radius-helper:8080/check}"
URN_PREFIX="${URN_PREFIX:-urn:example.com}"
EXPECTED_ISSUER_CN="${EXPECTED_ISSUER_CN:?EXPECTED_ISSUER_CN env var is required (issuing CA's CN)}"

fail() {
  echo "$(date -Iseconds) FAIL: $*" >> "$LOG"
  exit 1
}

passlog() {
  echo "$(date -Iseconds) PASS: $*" >> "$LOG"
}

echo "============================================================" >> "$LOG"
echo "$(date -Iseconds) verify start cert=${CERT} username=${RADIUS_USERNAME} callingStationId=${CALLING_STATION_ID}" >> "$LOG"

[ -n "$CERT" ] || fail "missing cert path"
[ -f "$CERT" ] || fail "cert file does not exist: $CERT"

openssl x509 -in "$CERT" -noout >/dev/null 2>&1 || fail "openssl could not parse client cert"

openssl verify -CAfile /etc/freeradius/certs/ca-chain.pem "$CERT" >> "$LOG" 2>&1 || fail "openssl chain verification failed"

openssl x509 -in "$CERT" -noout -checkend 0 >/dev/null 2>&1 || fail "cert expired"
echo "Certificate is currently within its validity period" >> "$LOG"

SUBJECT="$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null || true)"
ISSUER="$(openssl x509 -in "$CERT" -noout -issuer 2>/dev/null || true)"
DATES="$(openssl x509 -in "$CERT" -noout -dates 2>/dev/null || true)"
TEXT="$(openssl x509 -in "$CERT" -noout -text 2>/dev/null || true)"

echo "$SUBJECT" >> "$LOG"
echo "$ISSUER" >> "$LOG"
echo "$DATES" >> "$LOG"

echo "$ISSUER" | grep -q "CN *= *${EXPECTED_ISSUER_CN}" || fail "issuer CN is not ${EXPECTED_ISSUER_CN}"

echo "$TEXT" | grep -A3 "X509v3 Extended Key Usage" | grep -q "TLS Web Client Authentication" || fail "missing Client Authentication EKU"

echo "$TEXT" | grep -q "URI:${URN_PREFIX}:entra-device-id:" || \
echo "$TEXT" | grep -q "URI:${URN_PREFIX}:entra-user-id:" || \
echo "$TEXT" | grep -q "URI:${URN_PREFIX}:user-upn:" || \
fail "missing expected ${URN_PREFIX} SAN URI"

awk '
BEGIN {
  printf("{")
  printf("\"cert_pem\":\"")
}
{
  gsub(/\\/,"\\\\")
  gsub(/"/,"\\\"")
  printf("%s\\n", $0)
}
END {
  printf("\",")
  printf("\"radius_username\":\"%s\",", ENVIRON["RADIUS_USERNAME"])
  printf("\"calling_station_id\":\"%s\"", ENVIRON["CALLING_STATION_ID"])
  printf("}")
}
' "$CERT" > /tmp/intune-radius-helper-request.json

HTTP_CODE="$(curl -sS -o /tmp/intune-radius-helper-response.json -w "%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  --data @/tmp/intune-radius-helper-request.json \
  "$HELPER_URL" 2>> "$LOG")"

echo "Helper HTTP ${HTTP_CODE}" >> "$LOG"
cat /tmp/intune-radius-helper-response.json >> "$LOG"
echo >> "$LOG"

[ "$HTTP_CODE" = "200" ] || fail "helper denied or errored"

passlog "certificate and helper policy allowed"
exit 0
