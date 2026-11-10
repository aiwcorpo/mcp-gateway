# Install mcp-gateway

The gateway with its own PostgreSQL and Redis (primary and replica) on one Linux host with Docker. To install it together with the broker, portal and identity provider, use the Compose bundle in `mcp-platform` instead. The steps below are for a gateway on its own.

## Requirements

- Linux, Docker Engine with Compose v2.20 or newer, 2 GiB of memory.
- A certificate for the gateway from your internal CA (CN `mcp-gateway`, SAN `mcp-gateway.internal`, for server and client use) and the CA certificate.
- The address of the identity provider and of the credential broker.
- A TLS reverse proxy for the public address. It forwards `/mcp`, `/s/`, `/.well-known/oauth-protected-resource` and `/.well-known/mcp-jwks.json` to port 8080.

## Install

1. Download and unpack this directory:

    ```bash
    curl -LO https://github.com/aiwcorpo/mcp-gateway/releases/download/v2.0.0/mcp-gateway-deploy.tar.gz
    tar xzf mcp-gateway-deploy.tar.gz && cd mcp-gateway-deploy
    ```

2. Build the two stores in `certs/`. Use one password for both:

    ```bash
    openssl pkcs12 -export -inkey gateway.key -in gateway.crt -certfile ca.crt -name mcp-gateway -out certs/keystore.p12
    keytool -importcert -noprompt -alias ca -file ca.crt -keystore certs/truststore.p12 -storetype PKCS12
    ```

3. Fill in the empty values in `gateway.env`: `MCP_PUBLIC_URL`, `MCP_OIDC_ISSUER`, `MCP_OIDC_JWKS_URI`, `MCP_BROKER_URL` and `MCP_TLS_STORE_PASSWORD`.

4. If the identity provider has a certificate from your company CA, build a store with that CA and uncomment the `JAVA_TOOL_OPTIONS` line in `gateway.env`:

    ```bash
    keytool -importcert -noprompt -alias corp-ca -file corp-ca.crt -keystore certs/jvm-truststore.p12 -storetype PKCS12 -storepass changeit
    ```

5. Start the gateway:

    ```bash
    docker compose up -d
    ```

6. Read the check that `init` runs before every start:

    ```bash
    docker compose logs init
    ```

    Expected: `ok` lines. A `FAIL` stops the start: fix it and run `docker compose up -d` again. A `warn` does not, because the broker may be installed after the gateway.

On the first start `init` generates the passwords of PostgreSQL and Redis, the internal JWT keys and the cursor keys, and keeps them in Docker volumes.

## Check that it works

```bash
curl -fsSk https://localhost:8443/actuator/health
```

Expected: `{"status":"UP"...}`.

## Add servers to the platform

An administrator adds each MCP server by its address in the portal (Administration, Servers) with a fresh login and OTP. Nothing restarts.

1. Servers, Add server: `https://<server host>:8443/mcp`. For a server on the Docker network of the platform use `http://...` and tick "allow plain http". The gateway reads the certificate, pulls the manifest and shows the server as `pending_approval`.
2. Approve the connection. Compare the fingerprint on the card with the one in the server log. A certificate signed by a CA the gateway trusts is accepted as `ca`; any other is pinned by its fingerprint.
3. Approve the policies, then every tool. Tools that only read wait for approval too.
4. In Scope mapping, map groups to the resources of the server. In the identity provider, create the groups `mcp-<system>-read`, `-write`, `-destructive` that the server uses and add the users.

To remove a server, delete it in the portal. Its tools leave every tool list.

## Common problems

| Symptom | Cause | Fix |
| --- | --- | --- |
| `init`: `FAIL identity provider keys ...: the name does not resolve` | DNS or `/etc/hosts` of this host | Fix the name resolution, run `docker compose up -d` |
| `init`: identity provider certificate not trusted | The identity provider uses a company CA | Do step 4 |
| `init`: `warn broker ...: connection refused` | The broker is not running yet | Start the broker; the gateway starts anyway |
| Add server: `plain_http_not_allowed` | An `http://` address without "allow plain http" | Tick it, only for servers on the Docker network of the platform |
| Server status `certificate_changed` | A pinned server presented another certificate | Approve the new fingerprint |
| Tool call: `upstream_unavailable`, server `unreachable` | The server does not answer on its address | Check the address, the port and the server log |

## Ports

| Port | For |
| --- | --- |
| 8080 | MCP clients through your reverse proxy, plain HTTP. Bound to 127.0.0.1; for a proxy on another host set `GATEWAY_HTTP_BIND=0.0.0.0` in a `.env` file here. |
| 8443 | TLS with the gateway certificate: the admin API, `/actuator/health`, and the internal JWT keys that the broker fetches. MCP servers fetch the keys from the public address (`/.well-known/mcp-jwks.json`, port 8080). |

## Several instances

Instances behind one address share PostgreSQL, Redis, the file of internal JWT keys and the cursor keys (`MCP_INTERNAL_JWT_KEYS_FILE`, `MCP_INTERNAL_JWT_ACTIVE_KID`, `MCP_LIST_CURSOR_KEY`, `MCP_ACTIVITY_CURSOR_KEY`) and the same `MCP_ALLOWED_CLIENTS`. A change of servers or approvals reaches the other instances within a second.

## Refused server addresses

The gateway refuses servers at loopback, link-local, unspecified, multicast and cloud metadata addresses. To refuse more, set `MCP_SERVER_REFUSED_ADDRESSES` in `gateway.env` (comma-separated addresses or CIDR ranges). For a company CA on the servers, set `MCP_SERVER_TRUSTED_CAS` to a PEM file with the CA certificates and put the file next to the other certificates.

## Closed network

Copy the images to your registry and set them in a `.env` file next to `compose.yaml`:

```bash
MCP_REGISTRY=artifactory.corp.test/mcp
MCP_THIRD_PARTY_REGISTRY=artifactory.corp.test/dockerhub
```

## Upgrade

Change `MCP_GATEWAY_VERSION` in `.env` (or download the new directory) and run `docker compose up -d`. The generated keys and passwords stay.

From 1.x: servers listed in `gateway.env` are not read any more; add them in the portal as above.

## Virtual machine without Docker

`systemd/` has a unit and its environment file for the jar, with your own PostgreSQL and Redis (with a replica). The unit runs `init` before every start; its state is in `/var/lib/mcp-gateway/secrets`.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin gateway
sudo install -d -o root -g gateway -m 0750 /etc/mcp-gateway /opt/mcp-gateway
sudo install -m 0644 mcp-gateway.jar /opt/mcp-gateway/gateway.jar
sudo install -o root -g gateway -m 0640 systemd/mcp-gateway.env /etc/mcp-gateway/mcp-gateway.env
sudo install -m 0644 systemd/mcp-gateway.service /etc/systemd/system/
```

Fill in `/etc/mcp-gateway/mcp-gateway.env`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-gateway
```
