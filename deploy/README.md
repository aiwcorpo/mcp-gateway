# Install the gateway

The gateway with its own PostgreSQL and Redis on one Linux host with Docker. The other components (identity provider, credential
broker, MCP servers) run elsewhere; you give the addresses of the first two here and add the servers afterwards.

## Prerequisites

- Linux, Docker Engine with Compose v2.20 or newer, 2 GiB of memory for the gateway.
- From your internal CA: a certificate for the gateway with CN `mcp-gateway` and SAN `mcp-gateway.internal`, for server and client
  use, and the CA certificate.
- The address of the identity provider and of the credential broker.
- A TLS reverse proxy for the public address. It forwards `/mcp`, `/s/` and `/.well-known/oauth-protected-resource` to port 8080.

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

1. In the portal (Administration, Servers), or with the admin API, add the server: its `serverId` is `mcp-<system>`, the address is its
   internal HTTPS URL, and the credential says how the broker gets the user's credential for it. The certificate of the server comes
   from the internal CA with CN `mcp-<system>` and SAN `mcp-<system>.internal` (server and client use); the gateway accepts no other
   certificate for it. Adding, changing (except switching off with `enabled: false`) and removing a server, and approving policies,
   need a token of a fresh MFA login (`auth_time` within 5 minutes and an `amr` of `mfa`, `otp`, `hwk` or `totp`, or an `acr` listed in
   `MCP_ADMIN_MFA_ACR_VALUES`).

    ```bash
    curl --cert bff.crt --key bff.key --cacert ca.crt -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
      https://gateway.corp.internal:8443/admin/v1/servers -d '{"serverId":"mcp-notes","system":"notes",
      "internalUrl":"https://mcp-notes.corp.internal:8443/mcp","credential":{"required":true,"acceptedTypes":["user-oauth"],"type":"user-oauth"}}'
    ```

2. The server's pipeline registers its manifest (`PUT /admin/v1/registry/servers/mcp-notes`). Tools that only read are approved by that
   call; the others, and the policies of the server, wait in the portal.
3. Approve the policies (and the tools that wait). Until then the server has no tools for anyone.
4. Add the system in the credential broker if it is new, and map groups to the resources of the server (Administration, Scope mapping).

### Remove a server

Delete it in the portal, or `DELETE /admin/v1/servers/mcp-notes`. Its tools leave every `tools/list` and clients are told that the list
changed; calls are refused as for an unknown tool. Its approvals, policies and emergency switches go with it, so do the entries of the
scope mapping for its resource types, and its name is free again. The system in the broker is removed there.

### Change a server

`PATCH /admin/v1/servers/mcp-notes` with `internalUrl`, `credential` or `enabled` and `If-Match` set to the `ETag` of the last `GET`
(whether a server is an adapter is set when it is added). `enabled: false` takes a
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
| 8443 | TLS with the gateway certificate: the broker and the MCP servers fetch the internal JWT keys here. |

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
