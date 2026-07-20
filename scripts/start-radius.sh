#!/bin/sh
# freeradius-wifi-eap-tls - EAP-TLS RADIUS server generating client/VLAN config from env vars
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

RADIUS_CLIENT_NAME_RAW="${RADIUS_CLIENT_NAME:-wifi_infra}"
RADIUS_CLIENT_NAME="$(printf '%s' "$RADIUS_CLIENT_NAME_RAW" | sed 's/[^A-Za-z0-9_]/_/g')"

RADIUS_CLIENT_IPADDRS="${RADIUS_CLIENT_IPADDRS:-${RADIUS_CLIENT_IPADDR:-}}"
RADIUS_VLAN_ID="${RADIUS_VLAN_ID:-10}"
FREERADIUS_DEBUG="${FREERADIUS_DEBUG:-true}"

if [ -z "$RADIUS_CLIENT_IPADDRS" ]; then
  echo "ERROR: RADIUS_CLIENT_IPADDRS or RADIUS_CLIENT_IPADDR is required"
  exit 1
fi

if [ -z "${RADIUS_SHARED_SECRET:-}" ]; then
  echo "ERROR: RADIUS_SHARED_SECRET is required"
  exit 1
fi

mkdir -p /var/run/freeradius/tls-tmp
chown -R freerad:freerad /var/run/freeradius/tls-tmp 2>/dev/null || true
chmod 700 /var/run/freeradius/tls-tmp

cat > /etc/freeradius/clients.conf <<CLIENTS_EOF
client localhost {
    ipaddr = 127.0.0.1
    secret = testing123
    require_message_authenticator = no
    nas_type = other
}

CLIENTS_EOF

i=1
OLD_IFS="$IFS"
IFS=","
for ip in $RADIUS_CLIENT_IPADDRS; do
  ip="$(printf '%s' "$ip" | xargs)"
  if [ -n "$ip" ]; then
    cat >> /etc/freeradius/clients.conf <<CLIENT_EOF
client ${RADIUS_CLIENT_NAME}_${i} {
    ipaddr = ${ip}
    secret = ${RADIUS_SHARED_SECRET}
    require_message_authenticator = no
    nas_type = other
}

CLIENT_EOF
    i=$((i + 1))
  fi
done
IFS="$OLD_IFS"

if [ "${ENABLE_CRL_VERIFICATION:-false}" = "true" ] || [ "${ENABLE_CRL_VERIFICATION:-false}" = "yes" ] || [ "${ENABLE_CRL_VERIFICATION:-false}" = "1" ]; then
  CRL_BLOCK='
        check_crl = yes
        check_all_crl = no
        ca_path = /etc/freeradius/certs'
else
  CRL_BLOCK='
        check_crl = no'
fi

cat > /etc/freeradius/mods-enabled/eap <<EAP_EOF
eap {
    default_eap_type = tls
    timer_expire = 60
    ignore_unknown_eap_types = no
    cisco_accounting_username_bug = no
    max_sessions = \${max_requests}

    tls-config tls-common {
        private_key_password =
        private_key_file = /etc/freeradius/certs/radius-server.key
        certificate_file = /etc/freeradius/certs/radius-server-chain.pem
        ca_file = /etc/freeradius/certs/ca-chain.pem

        random_file = /dev/urandom

        fragment_size = 1024
        include_length = yes
        auto_chain = no

        tls_min_version = "1.2"
        tls_max_version = "1.3"

        require_client_cert = yes
${CRL_BLOCK}

        verify {
            tmpdir = /var/run/freeradius/tls-tmp
            client = "/usr/local/bin/verify-client-cert.sh %{TLS-Client-Cert-Filename} '%{User-Name}' '%{Calling-Station-Id}'"
        }
    }

    tls {
        tls = tls-common
    }
}
EAP_EOF

if [ -n "$RADIUS_VLAN_ID" ] && [ "$RADIUS_VLAN_ID" != "none" ] && [ "$RADIUS_VLAN_ID" != "false" ]; then
  POST_AUTH_BLOCK='
    post-auth {
        update reply {
            Tunnel-Type = VLAN
            Tunnel-Medium-Type = IEEE-802
            Tunnel-Private-Group-Id = "'"$RADIUS_VLAN_ID"'"
        }
    }'
else
  POST_AUTH_BLOCK='
    post-auth {
    }'
fi

cat > /etc/freeradius/sites-enabled/default <<SITE_EOF
server default {
    listen {
        type = auth
        ipaddr = *
        port = 1812
    }

    listen {
        type = acct
        ipaddr = *
        port = 1813
    }

    authorize {
        filter_username
        preprocess

        eap {
            ok = return
            updated = return
        }

        reject
    }

    authenticate {
        eap
    }
${POST_AUTH_BLOCK}

    Post-Auth-Type REJECT {
        attr_filter.access_reject
    }
}
SITE_EOF

echo "Generated /etc/freeradius/clients.conf:"
sed -E "s/(secret = ).*/\1****/" /etc/freeradius/clients.conf

echo
echo "Generated EAP config key lines:"
grep -nE "tmpdir|check_crl|ca_path|require_client_cert|private_key_file|certificate_file|ca_file|verify|client =" /etc/freeradius/mods-enabled/eap || true

echo
echo "Generated site VLAN config:"
grep -nA8 -B2 "Tunnel-Private-Group-Id\|post-auth" /etc/freeradius/sites-enabled/default || true

echo
echo "FREERADIUS_DEBUG=${FREERADIUS_DEBUG}"

if [ "$FREERADIUS_DEBUG" = "true" ] || [ "$FREERADIUS_DEBUG" = "yes" ] || [ "$FREERADIUS_DEBUG" = "1" ]; then
  exec freeradius -X
else
  exec freeradius -f
fi
