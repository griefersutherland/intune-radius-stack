#!/bin/sh
# freeradius-wifi-eap-tls - EAP-TLS RADIUS server generating per-site client/VLAN config from env vars
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

FREERADIUS_DEBUG="${FREERADIUS_DEBUG:-true}"

EXPECTED_ISSUER_CN="${EXPECTED_ISSUER_CN:?EXPECTED_ISSUER_CN env var is required (issuing CA's CN)}"
URN_PREFIX="${URN_PREFIX:-urn:example.com}"
HELPER_URL="${HELPER_URL:-http://intune-radius-helper:8080/check}"
CERT_STAGE_DIR="${CERT_STAGE_DIR:-/var/run/freeradius/cert-stage}"

validate_vlan_tag() {
  # $1 = env var name (for error messages), $2 = tag value
  case "$2" in
    ''|*[!0-9]*)
      echo "ERROR: ${1} must be a numeric VLAN ID (1-4094), got '${2}'"
      exit 1
      ;;
  esac
  if [ "$2" -lt 1 ] || [ "$2" -gt 4094 ]; then
    echo "ERROR: ${1}=${2} is out of the valid VLAN ID range (1-4094)"
    exit 1
  fi
}

# Sites are discovered dynamically, not from a fixed list: any env var named
# NAS_CIDR_<SITE> defines a site (<SITE> can be anything matching
# [A-Za-z0-9_]+ - that's all a shell env var name can contain anyway, so no
# separate validation is needed there). Each site needs NAS_CIDR_<SITE> (its
# NAS IP/CIDR, comma-separated for multiple per site) and NAS_SECRET_<SITE>.
# VLAN_ACCESS_WIFI_<SITE>, VLAN_ACCESS_WIRED_<SITE>, VLAN_UNTRUST_WIFI_<SITE>,
# VLAN_UNTRUST_WIRED_<SITE> are each independently optional, same semantics
# as the old global WIFI/WIRED_*_VLAN_* vars had, just per site now instead
# of shared across every client.
SITES="$(env | sed -n 's/^NAS_CIDR_\([A-Za-z0-9_]\{1,\}\)=.*/\1/p' | sort -u)"

if [ -z "$SITES" ]; then
  echo "ERROR: no sites defined - set at least one NAS_CIDR_<SITE> and NAS_SECRET_<SITE> pair"
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

# Built up per-site below, then wrapped in a switch on Client-Shortname (the
# name of whichever client{} block matched the request's source IP - set
# explicitly per site so it's unambiguous even with multiple NAS_CIDR
# entries for the same site).
SITE_SWITCH_CASES=""

for SITE in $SITES; do
  eval "SITE_NAS_CIDR=\"\${NAS_CIDR_${SITE}}\""
  eval "SITE_NAS_SECRET=\"\${NAS_SECRET_${SITE}:-}\""
  eval "SITE_VLAN_ACCESS_WIFI=\"\${VLAN_ACCESS_WIFI_${SITE}:-}\""
  eval "SITE_VLAN_ACCESS_WIRED=\"\${VLAN_ACCESS_WIRED_${SITE}:-}\""
  eval "SITE_VLAN_UNTRUST_WIFI=\"\${VLAN_UNTRUST_WIFI_${SITE}:-}\""
  eval "SITE_VLAN_UNTRUST_WIRED=\"\${VLAN_UNTRUST_WIRED_${SITE}:-}\""

  if [ -z "$SITE_NAS_SECRET" ]; then
    echo "ERROR: NAS_SECRET_${SITE} is required (site ${SITE} defines NAS_CIDR_${SITE} but no secret)"
    exit 1
  fi

  [ -z "$SITE_VLAN_ACCESS_WIFI" ] || validate_vlan_tag "VLAN_ACCESS_WIFI_${SITE}" "$SITE_VLAN_ACCESS_WIFI"
  [ -z "$SITE_VLAN_ACCESS_WIRED" ] || validate_vlan_tag "VLAN_ACCESS_WIRED_${SITE}" "$SITE_VLAN_ACCESS_WIRED"
  [ -z "$SITE_VLAN_UNTRUST_WIFI" ] || validate_vlan_tag "VLAN_UNTRUST_WIFI_${SITE}" "$SITE_VLAN_UNTRUST_WIFI"
  [ -z "$SITE_VLAN_UNTRUST_WIRED" ] || validate_vlan_tag "VLAN_UNTRUST_WIRED_${SITE}" "$SITE_VLAN_UNTRUST_WIRED"

  i=1
  OLD_IFS="$IFS"
  IFS=","
  for ip in $SITE_NAS_CIDR; do
    ip="$(printf '%s' "$ip" | xargs)"
    if [ -n "$ip" ]; then
      cat >> /etc/freeradius/clients.conf <<CLIENT_EOF
client ${SITE}_${i} {
    ipaddr = ${ip}
    secret = ${SITE_NAS_SECRET}
    shortname = ${SITE}
    require_message_authenticator = no
    nas_type = other
}

CLIENT_EOF
      i=$((i + 1))
    fi
  done
  IFS="$OLD_IFS"

  if [ "$i" -eq 1 ]; then
    echo "ERROR: NAS_CIDR_${SITE} did not contain any usable IP/CIDR entries"
    exit 1
  fi

  ACCESS_BRANCHES=""
  if [ -n "$SITE_VLAN_ACCESS_WIFI" ]; then
    ACCESS_BRANCHES="${ACCESS_BRANCHES}
                    if (&NAS-Port-Type == \"Wireless-802.11\") {
                        update reply {
                            Tunnel-Type = VLAN
                            Tunnel-Medium-Type = IEEE-802
                            Tunnel-Private-Group-Id = \"${SITE_VLAN_ACCESS_WIFI}\"
                        }
                    }"
  fi
  if [ -n "$SITE_VLAN_ACCESS_WIRED" ]; then
    ACCESS_BRANCHES="${ACCESS_BRANCHES}
                    if (&NAS-Port-Type == \"Ethernet\") {
                        update reply {
                            Tunnel-Type = VLAN
                            Tunnel-Medium-Type = IEEE-802
                            Tunnel-Private-Group-Id = \"${SITE_VLAN_ACCESS_WIRED}\"
                        }
                    }"
  fi

  UNTRUST_BRANCHES=""
  if [ -n "$SITE_VLAN_UNTRUST_WIFI" ]; then
    UNTRUST_BRANCHES="${UNTRUST_BRANCHES}
                    if (&NAS-Port-Type == \"Wireless-802.11\") {
                        update reply {
                            Tunnel-Type = VLAN
                            Tunnel-Medium-Type = IEEE-802
                            Tunnel-Private-Group-Id = \"${SITE_VLAN_UNTRUST_WIFI}\"
                        }
                        update control {
                            Tmp-String-1 := \"yes\"
                        }
                    }"
  fi
  if [ -n "$SITE_VLAN_UNTRUST_WIRED" ]; then
    UNTRUST_BRANCHES="${UNTRUST_BRANCHES}
                    if (&NAS-Port-Type == \"Ethernet\") {
                        update reply {
                            Tunnel-Type = VLAN
                            Tunnel-Medium-Type = IEEE-802
                            Tunnel-Private-Group-Id = \"${SITE_VLAN_UNTRUST_WIRED}\"
                        }
                        update control {
                            Tmp-String-1 := \"yes\"
                        }
                    }"
  fi

  SITE_SWITCH_CASES="${SITE_SWITCH_CASES}
            case \"${SITE}\" {
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
done

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

# Policy decisions (access/untrust/reject) happen here in post-auth via
# check-policy.sh, not in verify-client-cert.sh - TLS-Client-Cert-Filename
# does not persist from the verify{} hook into post-auth (confirmed
# empirically), so the actual compliance call had to move to where FreeRADIUS
# can natively branch on the result. Client-Shortname (set explicitly per
# site above) picks the site; NAS-Port-Type (which the AP/switch must
# actually send) picks the medium within it.
#
# "Access" without a configured VLAN for the matching site+medium is a plain
# accept (no VLAN attributes). "Untrust" without a configured VLAN for the
# matching site+medium rejects instead of leaving an untrusted client on an
# unspecified/default network - untrust existing at all implies you intend
# to contain it somewhere specific.
POST_AUTH_BLOCK="
    post-auth {
        update control {
            Tmp-String-0 := \"%{exec:/usr/local/bin/check-policy.sh %{Calling-Station-Id} %{User-Name}}\"
        }
        switch \"%{Client-Shortname}\" {${SITE_SWITCH_CASES}
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
grep -nA6 -B1 "Tunnel-Private-Group-Id\|switch \"%{Client-Shortname}\"\|case \"" /etc/freeradius/sites-enabled/default || true

echo
echo "Sites configured:"
for SITE in $SITES; do
  eval "SITE_NAS_CIDR=\"\${NAS_CIDR_${SITE}}\""
  eval "SITE_VLAN_ACCESS_WIFI=\"\${VLAN_ACCESS_WIFI_${SITE}:-}\""
  eval "SITE_VLAN_ACCESS_WIRED=\"\${VLAN_ACCESS_WIRED_${SITE}:-}\""
  eval "SITE_VLAN_UNTRUST_WIFI=\"\${VLAN_UNTRUST_WIFI_${SITE}:-}\""
  eval "SITE_VLAN_UNTRUST_WIRED=\"\${VLAN_UNTRUST_WIRED_${SITE}:-}\""
  echo "  ${SITE}: nas=${SITE_NAS_CIDR} wifi_access=${SITE_VLAN_ACCESS_WIFI:-none} wired_access=${SITE_VLAN_ACCESS_WIRED:-none} wifi_untrust=${SITE_VLAN_UNTRUST_WIFI:-none} wired_untrust=${SITE_VLAN_UNTRUST_WIRED:-none}"
done

echo
echo "FREERADIUS_DEBUG=${FREERADIUS_DEBUG}"

if [ "$FREERADIUS_DEBUG" = "true" ] || [ "$FREERADIUS_DEBUG" = "yes" ] || [ "$FREERADIUS_DEBUG" = "1" ]; then
  exec freeradius -X
else
  exec freeradius -f
fi
