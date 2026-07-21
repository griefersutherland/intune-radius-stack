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
FREERADIUS_DEBUG="${FREERADIUS_DEBUG:-true}"

EXPECTED_ISSUER_CN="${EXPECTED_ISSUER_CN:?EXPECTED_ISSUER_CN env var is required (issuing CA's CN)}"
URN_PREFIX="${URN_PREFIX:-urn:example.com}"
HELPER_URL="${HELPER_URL:-http://intune-radius-helper:8080/check}"
CERT_STAGE_DIR="${CERT_STAGE_DIR:-/var/run/freeradius/cert-stage}"

is_true() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    true|yes|1|on) return 0 ;;
    *) return 1 ;;
  esac
}

validate_vlan_tag() {
  # $1 = env var name (for error messages), $2 = tag value
  case "$2" in
    ''|*[!0-9]*)
      echo "ERROR: ${1} must be a numeric VLAN ID (1-4094) when its VLAN is enabled, got '${2}'"
      exit 1
      ;;
  esac
  if [ "$2" -lt 1 ] || [ "$2" -gt 4094 ]; then
    echo "ERROR: ${1}=${2} is out of the valid VLAN ID range (1-4094)"
    exit 1
  fi
}

WIFI_ACCESS_VLAN_ENABLED="${WIFI_ACCESS_VLAN_ENABLED:-false}"
WIFI_ACCESS_VLAN_TAG="${WIFI_ACCESS_VLAN_TAG:-}"
WIFI_UNTRUST_VLAN_ENABLED="${WIFI_UNTRUST_VLAN_ENABLED:-false}"
WIFI_UNTRUST_VLAN_TAG="${WIFI_UNTRUST_VLAN_TAG:-}"
WIRED_ACCESS_VLAN_ENABLED="${WIRED_ACCESS_VLAN_ENABLED:-false}"
WIRED_ACCESS_VLAN_TAG="${WIRED_ACCESS_VLAN_TAG:-}"
WIRED_UNTRUST_VLAN_ENABLED="${WIRED_UNTRUST_VLAN_ENABLED:-false}"
WIRED_UNTRUST_VLAN_TAG="${WIRED_UNTRUST_VLAN_TAG:-}"

is_true "$WIFI_ACCESS_VLAN_ENABLED" && validate_vlan_tag WIFI_ACCESS_VLAN_TAG "$WIFI_ACCESS_VLAN_TAG"
is_true "$WIFI_UNTRUST_VLAN_ENABLED" && validate_vlan_tag WIFI_UNTRUST_VLAN_TAG "$WIFI_UNTRUST_VLAN_TAG"
is_true "$WIRED_ACCESS_VLAN_ENABLED" && validate_vlan_tag WIRED_ACCESS_VLAN_TAG "$WIRED_ACCESS_VLAN_TAG"
is_true "$WIRED_UNTRUST_VLAN_ENABLED" && validate_vlan_tag WIRED_UNTRUST_VLAN_TAG "$WIRED_UNTRUST_VLAN_TAG"

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

mkdir -p "$CERT_STAGE_DIR"
chown -R freerad:freerad "$CERT_STAGE_DIR" 2>/dev/null || true
chmod 700 "$CERT_STAGE_DIR"

# verify-client-cert.sh and check-policy.sh are invoked by FreeRADIUS's own
# verify{} hook and %{exec:...} xlat respectively - neither inherits this
# container's environment (confirmed empirically: FreeRADIUS builds a fresh
# environment from request attributes for external programs), so config
# values are baked in here instead of read at runtime by those scripts.
cat > /etc/freeradius/verify-config.sh <<VERIFY_CONFIG_EOF
EXPECTED_ISSUER_CN="${EXPECTED_ISSUER_CN}"
URN_PREFIX="${URN_PREFIX}"
HELPER_URL="${HELPER_URL}"
CERT_STAGE_DIR="${CERT_STAGE_DIR}"
VERIFY_CONFIG_EOF

cat > /etc/freeradius/mods-enabled/exec <<'EXEC_EOF'
exec {
    wait = yes
    input_pairs = "request"
    shell_escape = yes
    timeout = 10
}
EXEC_EOF

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

# Policy decisions (access/untrust/reject) now happen here in post-auth via
# check-policy.sh, not in verify-client-cert.sh - TLS-Client-Cert-Filename
# does not persist from the verify{} hook into post-auth (confirmed
# empirically), so the actual compliance call had to move to where FreeRADIUS
# can natively branch on the result. Medium (wifi vs wired) is read from
# NAS-Port-Type, which the AP/switch must actually send.
#
# "Access" without a configured VLAN for the matching medium is a plain
# accept (no VLAN attributes) - same as before. "Untrust" without a
# configured VLAN for the matching medium rejects instead of leaving an
# untrusted client on an unspecified/default network - untrust existing at
# all implies you intend to contain it somewhere specific.
ACCESS_BRANCHES=""
if is_true "$WIFI_ACCESS_VLAN_ENABLED"; then
  ACCESS_BRANCHES="${ACCESS_BRANCHES}
                if (&NAS-Port-Type == \"Wireless-802.11\") {
                    update reply {
                        Tunnel-Type = VLAN
                        Tunnel-Medium-Type = IEEE-802
                        Tunnel-Private-Group-Id = \"${WIFI_ACCESS_VLAN_TAG}\"
                    }
                }"
fi
if is_true "$WIRED_ACCESS_VLAN_ENABLED"; then
  ACCESS_BRANCHES="${ACCESS_BRANCHES}
                if (&NAS-Port-Type == \"Ethernet\") {
                    update reply {
                        Tunnel-Type = VLAN
                        Tunnel-Medium-Type = IEEE-802
                        Tunnel-Private-Group-Id = \"${WIRED_ACCESS_VLAN_TAG}\"
                    }
                }"
fi

UNTRUST_BRANCHES=""
if is_true "$WIFI_UNTRUST_VLAN_ENABLED"; then
  UNTRUST_BRANCHES="${UNTRUST_BRANCHES}
                if (&NAS-Port-Type == \"Wireless-802.11\") {
                    update reply {
                        Tunnel-Type = VLAN
                        Tunnel-Medium-Type = IEEE-802
                        Tunnel-Private-Group-Id = \"${WIFI_UNTRUST_VLAN_TAG}\"
                    }
                    update control {
                        Tmp-String-1 := \"yes\"
                    }
                }"
fi
if is_true "$WIRED_UNTRUST_VLAN_ENABLED"; then
  UNTRUST_BRANCHES="${UNTRUST_BRANCHES}
                if (&NAS-Port-Type == \"Ethernet\") {
                    update reply {
                        Tunnel-Type = VLAN
                        Tunnel-Medium-Type = IEEE-802
                        Tunnel-Private-Group-Id = \"${WIRED_UNTRUST_VLAN_TAG}\"
                    }
                    update control {
                        Tmp-String-1 := \"yes\"
                    }
                }"
fi

POST_AUTH_BLOCK="
    post-auth {
        update control {
            Tmp-String-0 := \"%{exec:/usr/local/bin/check-policy.sh %{Calling-Station-Id} %{User-Name}}\"
        }
        switch \"%{control:Tmp-String-0}\" {
            case \"access\" {${ACCESS_BRANCHES}
            }
            case \"untrust\" {
                update control {
                    Tmp-String-1 := \"no\"
                }${UNTRUST_BRANCHES}
                if (\"%{control:Tmp-String-1}\" != \"yes\") {
                    reject
                }
            }
            case {
                reject
            }
        }
    }"

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
echo "VLAN policy (access/untrust tier is decided per-request by check-policy.sh; a tier with no VLAN configured for the matching medium falls back to plain accept for access, or reject for untrust):"
for _vlan_summary in \
  "wifi_access:${WIFI_ACCESS_VLAN_ENABLED}:${WIFI_ACCESS_VLAN_TAG}" \
  "wifi_untrust:${WIFI_UNTRUST_VLAN_ENABLED}:${WIFI_UNTRUST_VLAN_TAG}" \
  "wired_access:${WIRED_ACCESS_VLAN_ENABLED}:${WIRED_ACCESS_VLAN_TAG}" \
  "wired_untrust:${WIRED_UNTRUST_VLAN_ENABLED}:${WIRED_UNTRUST_VLAN_TAG}"
do
  _name="${_vlan_summary%%:*}"
  _rest="${_vlan_summary#*:}"
  _enabled="${_rest%%:*}"
  _tag="${_rest#*:}"
  if is_true "$_enabled"; then
    echo "  ${_name}: enabled, tag=${_tag}"
  else
    echo "  ${_name}: disabled"
  fi
done

echo
echo "FREERADIUS_DEBUG=${FREERADIUS_DEBUG}"

if [ "$FREERADIUS_DEBUG" = "true" ] || [ "$FREERADIUS_DEBUG" = "yes" ] || [ "$FREERADIUS_DEBUG" = "1" ]; then
  exec freeradius -X
else
  exec freeradius -f
fi
