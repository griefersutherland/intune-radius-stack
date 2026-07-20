#!/bin/sh
# intune-radius-stack - fills random values for locally-generated .env secrets
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
set -eu

cd "$(dirname "$0")/.."

FORCE=0
if [ "${1:-}" = "--force" ]; then
  FORCE=1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

set_secret() {
  var="$1"
  current="$(grep -E "^${var}=" .env | cut -d'=' -f2-)"
  if [ -n "$current" ] && [ "$FORCE" -ne 1 ]; then
    echo "  $var already set, skipping (use --force to overwrite)"
    return
  fi
  value="$(openssl rand -hex 32)"
  sed -i "s/^${var}=.*/${var}=${value}/" .env
  echo "  $var generated"
}

echo "Generating local secrets in .env..."
set_secret POSTGRES_PASSWORD
set_secret REDIS_PASSWORD
set_secret RADIUS_SHARED_SECRET

chmod 600 .env

cat <<'EOF'

Done. These still need to be filled in by hand (not generatable locally):
  TENANT_ID, CLIENT_ID, CLIENT_SECRET   - from the Entra app registration
  EXPECTED_ISSUER_CN                    - your PKI's issuing CA CN
  RADIUS_CLIENT_IPADDRS                 - your APs'/switches' IPs or CIDRs
  URN_PREFIX                            - must match what your PKI issues in cert SAN URIs

Note: POSTGRES_PASSWORD/REDIS_PASSWORD only take effect on a fresh
./data/postgres. If Postgres has already initialized once with a different
password, regenerating here won't rotate it in the running database -
you'd need ALTER USER inside the container, or a fresh volume.
EOF
