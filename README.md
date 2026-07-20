# intune-radius-stack

A docker-compose stack wiring together EAP-TLS FreeRADIUS with a Microsoft
Intune/Entra device-compliance gate, backed by Postgres + Redis caching. It
pulls two pre-built images:

- [freeradius-wifi-eap-tls](https://github.com/griefersutherland/freeradius-wifi-eap-tls) — FreeRADIUS, config generated from env vars
- [intune-radius-helper](https://github.com/griefersutherland/intune-radius-helper) — FastAPI service that checks client cert identity against Intune/Entra via Microsoft Graph

FreeRADIUS calls the helper over HTTP (`http://intune-radius-helper:8080/check`)
during the TLS handshake's certificate verify step; the helper looks up the
device/user identity embedded in the cert's SAN URIs against Microsoft Graph
(cached in Postgres, hot-cached in Redis) and allows or denies the auth.

## Prerequisites

You need your own PKI already set up:

- A CA (or chain) that issues client certificates carrying:
  - `TLS Web Client Authentication` EKU
  - a SAN URI under your `URN_PREFIX`, e.g. `urn:example.com:entra-device-id:<entra device id>`
- A server certificate/key for FreeRADIUS itself, signed by (or chaining to) that CA
- A Microsoft Entra ID app registration with Graph permissions to read
  `DeviceManagementManagedDevices.Read.All` and `User.Read.All`

This stack does not issue certificates or provision the Entra app for you.

## Setup

```
cp .env.example .env
# fill in TENANT_ID / CLIENT_ID / CLIENT_SECRET, RADIUS_SHARED_SECRET,
# EXPECTED_ISSUER_CN, POSTGRES_PASSWORD, REDIS_PASSWORD, etc.

mkdir -p certs logs data
# place ca-chain.pem, radius-server.key, radius-server-chain.pem (and a CRL
# if ENABLE_CRL_VERIFICATION=true) into ./certs

docker compose up -d
```

`docker compose logs -f freeradius` and `docker compose logs -f intune-radius-helper`
are your main debugging entry points; `curl http://localhost:8080/healthz`
from inside the `intune-radius-helper` container reports cache/backend health.

## Updating images

Both images are published on pushes to their respective repos'
`main`/tags. Pull the latest with:

```
docker compose pull
docker compose up -d
```

Pin specific versions in `docker-compose.yaml` (`:v0.1.0` etc.) if you want
controlled upgrades instead of tracking `:latest`.

## License

GPLv3 or later. See [LICENSE](LICENSE).
