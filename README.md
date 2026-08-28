# Servworx

Servworx monitors HTTP services and can restart an explicitly allowlisted set of Docker containers when health checks fail. The dashboard never receives the Docker socket: container logs and restart requests go through a separate, private broker that exposes only those two operations.

## Security model

- There is no default administrator password. First startup fails unless an operator supplies a password of at least 16 characters.
- Login is accepted only on a native TLS request or when `X-Forwarded-Proto: https` arrives from a configured trusted proxy CIDR.
- Session cookies are Secure, HttpOnly, and SameSite=Strict. Changing a password invalidates the user's other sessions.
- TLS verification for monitored HTTPS endpoints cannot be disabled. Private PKI is supported through `SERVWORX_CA_BUNDLE_FILE`.
- The dashboard image contains no Docker CLI and has no Docker socket mount.
- The broker is not published, requires a 32-character bearer secret, validates container names, and rejects every container outside `SERVWORX_ALLOWED_CONTAINERS`.
- Both services run as UID 65532 with read-only root filesystems, all capabilities dropped, and `no-new-privileges` enabled.

The broker still has high-value Docker authority inside its process. Keep its network private, use an exact allowlist, do not publish port 8080, and monitor Docker daemon events.

## Secure deployment

Requirements:

- Docker Engine and Docker Compose
- an HTTPS reverse proxy
- the numeric group ID that owns `/var/run/docker.sock`
- two secret files that are readable only by the deployment operator

Create the secrets and environment configuration:

```sh
mkdir -p secrets
openssl rand -base64 32 > secrets/admin-password
openssl rand -hex 32 > secrets/container-broker-token
chmod 600 secrets/admin-password secrets/container-broker-token
printf 'SERVWORX_ALLOWED_CONTAINERS=web-1,worker-1\nDOCKER_GID=%s\nSERVWORX_TRUSTED_PROXY_CIDRS=172.20.0.0/24\n' "$(stat -c '%g' /var/run/docker.sock)" > .env
chmod 600 .env
docker compose up -d --build
```

The published dashboard port defaults to `127.0.0.1:7676`. Terminate TLS at your reverse proxy, proxy to that port, and set `SERVWORX_TRUSTED_PROXY_CIDRS` to the narrow CIDR(s) from which the application actually sees that proxy. A forwarded header from any other address is ignored.

Open the HTTPS URL and sign in as `admin` with the value from `secrets/admin-password`. The bootstrap secret is used only when creating a new configuration or replacing the retired `changeme` credential. You may unmount/remove it after confirming the persisted configuration was created, but retain a controlled password-recovery procedure.

For a private certificate authority, mount a PEM bundle into the app container and set, for example:

```yaml
environment:
  SERVWORX_CA_BUNDLE_FILE: /app/config/ca/private-ca.pem
```

Never use a public or broadly shared proxy CIDR. Never publish the broker port. Never mount the Docker socket into the `monitor` service.

## Prebuilt images

The release workflow publishes two independently scanned images:

- `ghcr.io/arumes31/servworx:latest` — dashboard and monitor
- `ghcr.io/arumes31/servworx-broker:latest` — constrained Docker broker

Use [`docker-compose.ghcr.example.yaml`](docker-compose.ghcr.example.yaml) as the deployment reference. Pin released image digests in production rather than tracking `latest`.

## Configuration

Application state is stored in `/app/config/config.json` and `/app/config/status.json` with mode `0600`. The reference Compose file uses a named volume so UID 65532 can write it.

Each service has a monitored URL, accepted response codes, retry/interval/grace settings, and a comma-separated set of container names. Container names are additionally enforced by the broker allowlist; changing them in the UI does not expand Docker authority.

The legacy `insecure_skip_verify` JSON property is retained only for backward-compatible parsing and is ignored. Replace self-signed leaf certificates with a private CA and configure its bundle.

Notification providers are enabled through their existing `NOTIFICATION_*` environment variables. Treat webhook URLs, bot tokens, and SMTP credentials as secrets; inject them through your orchestrator rather than committing them.

## Migration from older releases

Before deploying this version:

1. Remove public access to the old dashboard.
2. Rotate the old `admin/changeme` credential and invalidate active sessions by restarting the application.
3. Review Docker events, container restarts, logs access, and reverse-proxy requests for unexpected activity.
4. Replace the dashboard's Docker socket mount with the broker service and define a minimal exact allowlist.
5. Configure the administrator and broker secret files.
6. Put the dashboard behind HTTPS and configure the proxy CIDR allowlist.
7. Remove every `insecure_skip_verify: true` setting and install the appropriate CA bundle.
8. Bring the stack up, verify that a spoofed forwarded header over direct HTTP cannot log in, and verify that non-allowlisted containers cannot be read or restarted.

## Development and verification

```sh
go test -race ./...
go vet ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 ./...
docker build --target app -t servworx-app:audit .
docker build --target broker -t servworx-broker:audit .
```

CI pins third-party actions, runs tests with the race detector, checks dependencies and static analysis, builds/scans both images from source, and publishes SBOM/provenance attestations on trusted pushes.

## Security reports

Please report vulnerabilities privately through GitHub Security Advisories. Do not include credentials, session cookies, webhook URLs, or Docker daemon details in a public issue.

## License

MIT — see [LICENSE](LICENSE).
