# intune-radius-stack

A docker-compose stack wiring together EAP-TLS FreeRADIUS with a Microsoft
Intune/Entra device-compliance gate, backed by Postgres + Redis caching.

- **freeradius** — the stock [`freeradius/freeradius-server`](https://hub.docker.com/r/freeradius/freeradius-server) image, unmodified. `scripts/start-radius.sh` and `scripts/verify-client-cert.sh` (GPLv3, in this repo) are bind-mounted in and installed as the container's entrypoint — no custom image to build or publish.
- [intune-radius-helper](https://github.com/griefersutherland/intune-radius-helper) — pre-built image; FastAPI service that checks client cert identity against Intune/Entra via Microsoft Graph

FreeRADIUS calls the helper over HTTP (`http://intune-radius-helper:8080/check`)
during the TLS handshake's certificate verify step; the helper looks up the
device/user identity embedded in the cert's SAN URIs against Microsoft Graph
(cached in Postgres, hot-cached in Redis) and allows or denies the auth.

`start-radius.sh` generates FreeRADIUS's `clients.conf`, EAP-TLS config, and
site config from env vars at container start; `verify-client-cert.sh` runs
per-auth as the EAP-TLS `verify { client = ... }` hook — checks the cert
chain, issuer CN, EKU, and SAN URI, then calls the helper. Because the
freeradius container has no custom image, it runs `apt-get install curl
ca-certificates` once at every container start (the stock image ships
`openssl` but not `curl`, which the verify hook needs) — adds a few seconds
to startup and needs outbound network access to Ubuntu's package mirrors. If
that's undesirable (offline hosts, faster restarts), build your own image
from this repo's `scripts/` instead and point `docker-compose.yaml` at it.

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

## Updating

Pull the latest upstream FreeRADIUS and helper images with:

```
docker compose pull
docker compose up -d
```

Pin a specific helper version in `docker-compose.yaml` (`:v0.1.0` etc.) if
you want controlled upgrades instead of tracking `:latest`. `scripts/*.sh`
are part of this repo, so `git pull` picks up changes to those directly.

## License

GPLv3 or later. See [LICENSE](LICENSE).
