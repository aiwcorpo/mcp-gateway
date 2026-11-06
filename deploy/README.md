# Install the gateway

The gateway with its own PostgreSQL and Redis on one Linux host with Docker. The other components (identity provider, credential
broker, policy server, MCP servers) run elsewhere; you give their addresses.

## Prerequisites

- Linux, Docker Engine with Compose v2.20 or newer, 2 GiB of memory for the gateway.
- From your internal CA: a certificate for the gateway with CN `mcp-gateway` and SAN `mcp-gateway.internal`, for server and client
  use, and the CA certificate.
- The address of the identity provider, the broker and the policy server, and the public key that signs the policy bundles.
- A TLS reverse proxy for the public address. It forwards `/mcp`, `/s/` and `/.well-known/oauth-protected-resource` to port 8080.

## Install

1. Download and unpack this directory:

    ```bash
    curl -LO https://github.com/aiwcorpo/mcp-gateway/releases/download/v1.1.0/mcp-gateway-deploy.tar.gz
    tar xzf mcp-gateway-deploy.tar.gz && cd mcp-gateway-deploy
    ```

2. Put three files in `certs/`:

    | File | What |
    | --- | --- |
    | `keystore.p12` | the gateway certificate and its key |
    | `truststore.p12` | the internal CA certificate |
    | `policies-main.public.pem` | the public key of the policy bundles (Ed25519, PEM) |

    Both stores use one password. From PEM files:

    ```bash
    openssl pkcs12 -export -inkey gateway.key -in gateway.crt -certfile ca.crt -name mcp-gateway -out certs/keystore.p12
    keytool -importcert -noprompt -alias ca -file ca.crt -keystore certs/truststore.p12 -storetype PKCS12
    ```

3. Fill in the empty values in `gateway.env` and turn on the MCP servers you run.
4. Start:

    ```bash
    docker compose up -d
    ```

The `init` service runs before the gateway on every start. On the first start it generates the passwords of PostgreSQL and Redis,
the internal JWT keys and the cursor keys, and keeps them in Docker volumes. Then it checks the configuration and the connections:

```console
$ docker compose logs init
ok    gateway certificate /certs/keystore.p12 and internal CA /certs/truststore.p12
ok    policy signing key /certs/policies-main.public.pem
ok    identity provider keys https://idp.corp.test/realms/corp/protocol/openid-connect/certs
FAIL  policy server https://policies.corp.test/policies/main/latest.json: the name does not resolve from this host (DNS or /etc/hosts)
warn  broker https://mcp-credential-broker.corp.test:8443: connection refused; nothing listens on that port, or the service is not running yet
```

A `FAIL` stops the start: fix it and run `docker compose up -d` again. A `warn` does not, because the broker and the MCP servers may
be installed after the gateway.

## Certificate of the identity provider

If the identity provider or the policy server has a certificate from your company CA, the JVM does not trust it and `init` says so.
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
passwords stay.

## Virtual machine without Docker

`systemd/` has a unit and its environment file for a gateway from the jar, with your own PostgreSQL and Redis (with a replica).
The unit runs the same `init` before every start, with the state in `/var/lib/mcp-gateway/secrets`.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin gateway
sudo install -d -o root -g gateway -m 0750 /etc/mcp-gateway /opt/mcp-gateway
sudo install -m 0644 mcp-gateway.jar /opt/mcp-gateway/gateway.jar
sudo install -o root -g gateway -m 0640 systemd/mcp-gateway.env /etc/mcp-gateway/mcp-gateway.env   # then fill it in
sudo install -m 0644 systemd/mcp-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now mcp-gateway
```
