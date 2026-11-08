# Install the gateway

The gateway with its own PostgreSQL and Redis on one Linux host with Docker. The other components (identity provider, credential
broker, MCP servers) run elsewhere; you give the addresses of the first two here and add the servers afterwards by their address.

## Prerequisites

- Linux, Docker Engine with Compose v2.20 or newer, 2 GiB of memory for the gateway.
- From your internal CA: a certificate for the gateway with CN `mcp-gateway` and SAN `mcp-gateway.internal`, for server and client
  use, and the CA certificate.
- The address of the identity provider and of the credential broker.
- A TLS reverse proxy for the public address. It forwards `/mcp`, `/s/`, `/.well-known/oauth-protected-resource` and
  `/.well-known/mcp-jwks.json` (the public keys that MCP servers verify the gateway's tokens with) to port 8080.

## Install

1. Download and unpack this directory:

    ```bash
    curl -LO https://github.com/aiwcorpo/mcp-gateway/releases/download/v2.0.0/mcp-gateway-deploy.tar.gz
    tar xzf mcp-gateway-deploy.tar.gz && cd mcp-gateway-deploy
    ```

2. Put two files in `certs/`:

    | File | What |
    | --- | --- |
    | `keystore.p12` | the gateway certificate and its key |
    | `truststore.p12` | the internal CA certificate |

    Both stores use one password. From PEM files:

    ```bash
    openssl pkcs12 -export -inkey gateway.key -in gateway.crt -certfile ca.crt -name mcp-gateway -out certs/keystore.p12
    keytool -importcert -noprompt -alias ca -file ca.crt -keystore certs/truststore.p12 -storetype PKCS12
    ```

3. Fill in the empty values in `gateway.env`.
4. Start:

    ```bash
    docker compose up -d
    ```

The `init` service runs before the gateway on every start. On the first start it generates the passwords of PostgreSQL and Redis,
the internal JWT keys and the cursor keys, and keeps them in Docker volumes. Then it checks the configuration and the connections:

```console
$ docker compose logs init
ok    gateway certificate /certs/keystore.p12 and internal CA /certs/truststore.p12
ok    allowed AI clients: claude-code, claude-ai (MCP_ALLOWED_CLIENTS not set)
FAIL  identity provider keys https://idp.corp.test/realms/corp/protocol/openid-connect/certs: the name does not resolve from this host (DNS or /etc/hosts)
warn  broker https://mcp-credential-broker.corp.test:8443: connection refused; nothing listens on that port, or the service is not running yet
```

A `FAIL` stops the start: fix it and run `docker compose up -d` again. A `warn` does not, because the broker may be installed after the
gateway.

## MCP servers

The servers are data of the gateway, not settings of this directory. Adding or removing one restarts nothing: every gateway instance reads
the change within a few seconds.

### Add a server

A server author builds the server from the template and runs it anywhere, with a certificate from a public or company CA, with the self-signed
certificate that the template generates at its first start, or over plain `http` inside the Docker network of the platform. You need its URL and
nothing else: no certificate from the internal CA is made for a server, the gateway presents no client certificate to it, and nobody creates a token.

1. In the portal (Administration, Servers), or with the admin API, add the server by its URL. The gateway checks the address (loopback,
   link-local, unspecified and multicast addresses are refused, whatever way they are written and whatever a name resolves to), reads the
   certificate, pulls the manifest from `/.well-known/mcp-manifest` and takes the `serverId` (`mcp-<system>`) from it. For `http` set
   `allowPlainHttp`. Adding, changing (except switching off), removing and every approval need a token of a fresh MFA login (`auth_time` within
   5 minutes and an `amr` of `mfa`, `otp`, `hwk` or `totp`, or an `acr` listed in `MCP_ADMIN_MFA_ACR_VALUES`).

    ```bash
    curl --cert bff.crt --key bff.key --cacert ca.crt -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
      https://gateway.corp.internal:8443/admin/v1/servers -d '{"internalUrl":"https://mcp-notes.corp.internal:8443/mcp"}'
    ```

    The answer shows the server as `pending_approval` with the certificate the gateway saw (`pendingConnection`: subject, issuer, names, end of
    validity and its SHA-256 fingerprint) and the trust it proposes.
2. Approve the connection with the fingerprint you checked with the author of the server: `ca` when the certificate is signed by a CA that the
   gateway trusts and names the host of the address (the default trust store of the JVM, plus the PEM bundle in `MCP_SERVER_TRUSTED_CAS` for a
   company CA: put the file next to the other certificates and set it in `gateway.env`), `pinned` for a self-signed certificate (or instead of
   `ca`, to be stricter), `plain` for `http`. A pinned server that later presents another certificate is `certificate_changed`, unreachable, and
   shows the new fingerprint for your approval; a `ca` server that renews its certificate needs nothing.
3. Approve the policies and the tools. Every tool waits, the ones that only read included, and a tool is listed and callable only when the
   connection, the policies and the tool are approved.
4. Add the system in the credential broker if it is new, and map groups to the resources of the server (Administration, Scope mapping).

The gateway looks at every server at least once a minute (the manifest, the certificate) and pushes it the policy data after every change and at
least once a minute. A changed definition or policy waits for approval like the first one; a server that cannot be reached is `unreachable` in the list
and its calls are refused as `upstream_unavailable`. `POST /admin/v1/servers/mcp-notes/refresh` looks at once (no fresh MFA; one per 5 seconds).
The server fetches its keys from `https://<your domain>/.well-known/mcp-jwks.json`: the reverse proxy forwards that path to port 8080 too.

### Remove a server

Delete it in the portal, or `DELETE /admin/v1/servers/mcp-notes`. Its tools leave every `tools/list` and clients are told that the list
changed; calls are refused as for an unknown tool; the gateway no longer looks at it. Its approvals, connection, policies and emergency switches go with it, so do the entries of the
scope mapping for its resource types, and its name is free again. The system in the broker is removed there.

### Change a server

`PATCH /admin/v1/servers/mcp-notes` with `credential` or `enabled` and `If-Match` set to the `ETag` of the last `GET`
(the address, `allowPlainHttp` and whether a server is an adapter are set when it is added: for another address remove the server and add it
again; for another certificate at the same address approve the connection). `enabled: false` takes a
server out of service and keeps its approvals.

## Certificate of the identity provider

If the identity provider has a certificate from your company CA, the JVM does not trust it and `init` says so.
Build a store with that CA and turn on the `JAVA_TOOL_OPTIONS` line in `gateway.env`:

```bash
keytool -importcert -noprompt -alias corp-ca -file corp-ca.crt -keystore certs/jvm-truststore.p12 -storetype PKCS12 -storepass changeit
```

## Ports

| Port | For |
| --- | --- |
| 8080 | MCP clients through your reverse proxy, plain HTTP. Bound to 127.0.0.1; for a proxy on another host set `GATEWAY_HTTP_BIND=0.0.0.0` in a `.env` file here. |
| 8443 | TLS with the gateway certificate: the broker fetches the internal JWT keys here, and the admin API is here. The MCP servers fetch the keys from the public address (`/.well-known/mcp-jwks.json`, port 8080). |

## Closed network

Copy the images to your registry and point Compose at it in a `.env` file next to `compose.yaml`:

```bash
MCP_REGISTRY=artifactory.corp.test/mcp
MCP_THIRD_PARTY_REGISTRY=artifactory.corp.test/dockerhub
```

## Upgrade

Change `MCP_GATEWAY_VERSION` in `.env` (or download the new directory) and run `docker compose up -d`. The generated keys and
passwords stay. From 1.x: the servers that `gateway.env` listed are not read any more; add them as above (CHANGELOG, 2.0.0).

## Virtual machine without Docker

`systemd/` has a unit and its environment file for a gateway from the jar, with your own PostgreSQL and Redis (with a replica).
The unit runs the same `init` before every start, with the state in `/var/lib/mcp-gateway/secrets`. With your own PostgreSQL and
Redis `init` writes no file for them (the passwords are in the environment file). If it did, the files would still be unreachable
for other users: the unit's `UMask=0077` makes `secrets/` mode 0700, whatever the mode of `/var/lib/mcp-gateway` itself.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin gateway
sudo install -d -o root -g gateway -m 0750 /etc/mcp-gateway /opt/mcp-gateway
sudo install -m 0644 mcp-gateway.jar /opt/mcp-gateway/gateway.jar
sudo install -o root -g gateway -m 0640 systemd/mcp-gateway.env /etc/mcp-gateway/mcp-gateway.env   # then fill it in
sudo install -m 0644 systemd/mcp-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now mcp-gateway
```
