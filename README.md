# mcp-gateway

MCP Gateway platformy MCP (strumień ws-05): jedyny punkt wejścia klientów AI. Uwierzytelnia użytkownika
tokenem z IdP (C1), pobiera z brokera poświadczenie użytkownika do systemu (C4), wystawia wewnętrzny JWT (C2)
i przekazuje wywołanie do serwera MCP po mTLS z nagłówkami C3. Każde wywołanie narzędzia zostawia zdarzenia
audytu C8 z jednym `requestId`.

Stan: kamień M1 (jeden serwer `mcp-jira`, konfiguracja statyczna zamiast rejestru). Co działa, czego nie ma i
odstępstwa: [STATUS.md](STATUS.md). Kontrakty: `mcp-contracts` 2.0.2.

## Moduły

| Moduł | Zawartość |
| --- | --- |
| `gateway` | aplikacja Spring Boot 4.1.0 (Java 25), obraz `mcp-gateway:dev` |
| `test-server` | minimalny serwer MCP w miejscu `mcp-jira` do testów i demo M1 (mTLS, weryfikacja C2 według wektorów, C3 do mocka Jiry, audyt C8). To nie jest produkt; prawdziwy serwer powstaje z `mcp-server-template` (ws-04) |

## Co robi gateway w M1

- **Wejście (klient):** `POST /s/<serverId>/mcp`, Streamable HTTP, odpowiedzi `application/json`.
  - era 2026-07-28 (bezstanowa): `_meta` w każdym żądaniu, nagłówki `MCP-Protocol-Version`, `Mcp-Method`,
    `Mcp-Name` sprawdzane względem treści (`-32020`), nieobsługiwana wersja `-32022` z listą wersji,
    `server/discover`, wyniki z `resultType`;
  - era 2025-03-26 .. 2025-11-25: `initialize`, `Mcp-Session-Id` (Redis, `gw:session:*`, sesja związana z
    `sub` tokenu; obcy `sub` -> 404 jak sesja nieznana), `DELETE` kończy sesję, `GET` -> 405;
  - metody: `tools/list`, `tools/call`, `ping`; nazwy narzędzi dla klienta `<system>__<tool>` (C5).
- **OAuth RS (C1):** JWT z JWKS IdP, `iss`, `aud` zawiera `mcp-gateway`, wymagane `sub`, `azp`,
  `preferred_username`; brak lub zły token -> `401` z `WWW-Authenticate: Bearer resource_metadata="..."`;
  dokument RFC 9728 pod `/.well-known/oauth-protected-resource/s/<serverId>/mcp`. Nic nie jest anonimowe poza
  metadanymi.
- **Autoryzacja (tymczasowa, M1):** `READ_ONLY` wymaga grupy `mcp-<system>-read`, `UPDATE` grupy
  `mcp-<system>-write`, `DESTRUCTIVE` zawsze odmowa (brak potwierdzeń przed M3). Interfejs `ToolAuthorizer` w M2
  dostaje implementację Cedar z `PolicyStore`. Narzędzie spoza konfiguracji jest ukryte i daje `tool_disabled`.
- **Poświadczenia (C4):** `POST /v1/credentials/resolve` po mTLS (certyfikat CN `mcp-gateway`, nazwa brokera
  z konfiguracji) z JWT C2 `aud=mcp-credential-broker` i `tool`; `409` -> `credential_required` z `connectUrl`;
  `503`, brak połączenia, timeout -> `upstream_unavailable`; inne odpowiedzi -> `internal_error`. Serwer nie
  dostaje wywołania bez poświadczenia. Dla systemów `token-exchange` gateway wymienia token użytkownika w IdP
  na `aud=mcp-credential-broker` i wysyła go jako `subjectToken`.
- **Cache poświadczeń:** w pamięci, klucz (`sub`, system, scopes), najwyżej `min(cacheTtlSeconds, 60 s,
  expiresAt)`. Subskrypcja Redis `credential.invalidated` usuwa wpisy (sub, system) od razu. Dopóki subskrypcja
  nie jest potwierdzona (start, awaria Redis, reconnect), cache jest wyczyszczony i pomijany.
- **Do serwera (C2, C3):** nowy JWT ES256 na każde żądanie HTTP (`exp - iat` = 30 s, `jti` UUIDv7),
  `tool` tylko przy `tools/call`; `grp` tylko grupy `mcp-*`; wariant użytkownika do `initialize`/`tools/list`
  (sesje są per użytkownik), wariant serwisowy tylko w `GET /v1/systems` brokera przy starcie. Nagłówki do
  serwera budowane od zera: `Authorization`, `X-Request-Id`, `X-MCP-Credential`, `X-MCP-Credential-Type`,
  `Mcp-Session-Id`, `MCP-Protocol-Version`; z żądania klienta nie jest kopiowany żaden nagłówek. Sesje do serwera
  mają klucz zawierający `sub`, nigdy nie są współdzielone; po `404` sesji gateway robi `initialize` ponownie.
  Certyfikat serwera musi mieć SAN `<serverId>.internal` niezależnie od adresu połączenia. Odpowiedź serwera
  (JSON albo SSE) czytana z twardym limitem bajtów (4 MiB).
- **JWKS wewnętrzny:** `https://<nazwa TLS>:8443/.well-known/jwks.json`, dwa `kid` (aktywny i następny).
  Klucze z pliku JWKS (`MCP_INTERNAL_JWT_KEYS_FILE`, `MCP_INTERNAL_JWT_ACTIVE_KID`) albo, bez pliku, dwa klucze
  generowane przy starcie. `kid` z prefiksem `test-` i opublikowane klucze testowe `mcp-contracts`
  (`PublishedTestKeys`) są odrzucane przy starcie.
- **Audyt C8:** logger `AUDIT`, jedna linia JSON na zdarzenie na stdout; na każde `tools/call` zdarzenia
  `policy_decision` i `tool_call` (bez wartości argumentów, tylko `argsLength`). `requestId` (UUIDv7) wraca do
  klienta w `X-Request-Id`; `X-Request-Id` klienta trafia do `clientRequestId`, jeśli pasuje do wzorca.
- **Metryki:** `/actuator/prometheus` (tylko port wewnętrzny): `mcp_gateway_tool_calls_total`,
  `mcp_gateway_tool_call_duration_seconds`, `mcp_gateway_credential_cache_total`,
  `mcp_gateway_broker_resolve_total`, `mcp_gateway_requests_total`.

Porty: `8080` (klienci MCP) i `8443` (TLS z certyfikatem gateway'a: JWKS, `/actuator/health`,
`/actuator/prometheus`). Port wewnętrzny nie obsługuje ścieżek MCP, port publiczny nie obsługuje JWKS ani
actuatora.

## Konfiguracja

Zmienne środowiska (nazwy z `mcp-platform-dev`, usługa `mcp-gateway` profilu `full`); pełna lista w
`gateway/src/main/resources/application.yml`.

| Zmienna | Znaczenie |
| --- | --- |
| `MCP_OIDC_ISSUER`, `MCP_OIDC_JWKS_URI`, `MCP_OIDC_AUDIENCE` | C1: oczekiwany `iss`, JWKS IdP, audience (domyślnie `mcp-gateway`) |
| `MCP_OIDC_AUTHORIZATION_SERVER` | serwer autoryzacji w RFC 9728; domyślnie `MCP_OIDC_ISSUER` |
| `MCP_OIDC_TOKEN_URI`, `MCP_OIDC_CLIENT_ID`, `MCP_OIDC_CLIENT_SECRET` | token exchange dla systemów `token-exchange` |
| `MCP_PUBLIC_URL` | publiczny adres gateway'a w metadanych; puste = schemat i host z żądania |
| `MCP_INTERNAL_PORT` | port wewnętrzny TLS, domyślnie `8443` |
| `MCP_INTERNAL_JWT_ISSUER` | `iss` C2, domyślnie `https://mcp-gateway.internal` |
| `MCP_INTERNAL_JWT_KEYS_FILE`, `MCP_INTERNAL_JWT_ACTIVE_KID` | prywatny JWKS (P-256) i aktywny `kid`; puste = klucze generowane |
| `MCP_TLS_KEYSTORE`, `MCP_TLS_TRUSTSTORE`, `MCP_TLS_STORE_PASSWORD` | PKCS12 gateway'a (CN `mcp-gateway`, serverAuth+clientAuth) i CA |
| `MCP_BROKER_URL`, `MCP_BROKER_TLS_NAME` | broker i nazwa w jego certyfikacie (CC-035) |
| `MCP_REDIS_HOST`, `MCP_REDIS_PORT`, `MCP_REDIS_USER`, `MCP_REDIS_PASSWORD`, `MCP_REDIS_KEY_PREFIX` | Redis (ACL `gateway`, `gw:*`, `credential.invalidated`) |
| `MCP_SERVER_JIRA_URL` albo `MCP_SERVER_JIRA_MCP_URL` | adres `mcp-jira`; do pierwszego dopisywane jest `/mcp` |
| `MCP_POLICY_REVISION` | `prv` w C2 do czasu paczki polityk (M2), domyślnie `00000000000000-0000000` |
| `MCP_ALLOWED_ORIGINS` | dozwolone `Origin` (lista); żądanie z innym `Origin` -> 403, bez `Origin` przechodzi |

Konfiguracja statyczna serwera (M1, w miejscu rejestru C5) jest w `application.yml`:

```yaml
gateway:
  servers:
    mcp-jira:
      system: jira
      internal-url: https://mcp-jira.internal:8443/mcp
      credential: {required: true, accepted-types: [user-secret, user-oauth]}
      tools:
        search_issues: {risk: READ_ONLY}
        get_issue: {risk: READ_ONLY}
        add_comment: {risk: UPDATE}
        transition_issue: {risk: UPDATE}
```

`serverId` musi być `mcp-<system>`, adres tylko `https`, nazwy narzędzi według `ToolName` z kontraktu; błąd
konfiguracji zatrzymuje start.

## Budowanie i testy

Wymaga JDK 25 i Dockera (Testcontainers: Redis z ACL jak w `mcp-platform-dev`).

```bash
export JAVA_HOME=/opt/homebrew/Cellar/openjdk@25/25.0.4.1/libexec/openjdk.jdk/Contents/Home
./mvnw -B install                                    # testy + jary obu modułów
docker build -t mcp-gateway:dev .
docker build -t mcp-gateway-test-server:dev -f test-server/Dockerfile .
```

| Test | Co sprawdza |
| --- | --- |
| `InternalJwtVerifierVectorTest` (test-server) | odbiorca C2 serwera testowego daje wynik i powód z każdego z 43 wektorów `test-vectors/jwt` |
| `InternalTokenIssuerTest` | JWT gateway'a zgodny z `internal-jwt.schema.json` i przyjmowany przez odbiorcę; `tool` tylko przy `tools/call`; wariant serwisowy tylko na `GET /v1/systems`; odrzucenie kluczy `test-` i opublikowanych kluczy testowych |
| `CredentialCacheTest`, `CredentialServiceTest` | TTL, `expiresAt`, unieważnienie (sub, system), wyścig resolve/unieważnienie, pomijanie cache bez subskrypcji, typ poświadczenia, token exchange |
| `StreamableHttpClientTest` | limit bajtów odpowiedzi (SSE bez znaku nowej linii, JSON), wybór odpowiedzi z SSE po `id` |
| `GatewayIntegrationTest` | prawdziwy gateway z IdP, brokerem i serwerem testowym po mTLS: 401 + RFC 9728, sesje i ich właściciel, obie ery protokołu, nagłówki klienta nie docierają do serwera, `credential_required`, `upstream_unavailable` (503 i zerwane połączenie), unieważnienie <= 1 s, TTL, SAN serwera, JWKS tylko na porcie wewnętrznym, audyt zgodny ze schematem C8, brak sekretów w logach |

## Uruchomienie lokalne w `mcp-platform-dev` (ws-01)

### Na hoście (sprawdzone 2026-10-27)

Infrastruktura z `make up`; gateway, broker i serwer testowy jako procesy na hoście, bez zmian w kontenerach
środowiska.

```bash
./mvnw -B install -DskipTests
# 1. broker (repo mcp-credential-broker) z JWKS tego gateway'a
(cd ../mcp-credential-broker && MCP_GATEWAY_JWKS_URI=https://localhost:18445/.well-known/jwks.json \
   MCP_GATEWAY_TLS_NAME=localhost scripts/run-dev-host.sh) &
# 2. gateway: http://localhost:18000, JWKS https://localhost:18445
scripts/run-dev-host.sh &
# 3. serwer testowy w miejscu mcp-jira: https://localhost:18446/mcp
scripts/run-test-server-host.sh &
# 4. PAT alice w brokerze i przebieg MCP z tokenem alice
(cd ../mcp-platform-dev && make pat USER=alice BROKER_URL=https://localhost:18100)
TOKEN=$(make -s -C ../mcp-platform-dev token USER=alice | tail -1) scripts/mcp-demo.sh
```

`scripts/mcp-demo.sh` wypisuje odpowiedzi i `X-Request-Id` każdego żądania. Zdarzenia jednego żądania z trzech
komponentów: logi procesów do pliku i `python3 ../mcp-platform-dev/scripts/mcpdev.py audit <requestId>
--logs <plik>` (to samo narzędzie co `make audit`, które czyta logi kontenerów). `make jira-auth` pokazuje, że do
Jiry dotarł `PAT alice-pat`.

### W compose (profil `full`)

Obraz `mcp-gateway:dev` pasuje do usługi `mcp-gateway`. Serwer testowy może zastąpić `mcp-jira` przez
`MCP_JIRA_IMAGE=mcp-gateway-test-server:dev`. Stuby C4/C5 (`broker-mock`, `gateway-admin-mock`) mają te same
aliasy DNS co broker i gateway, więc prawdziwe komponenty wymagają `make up-full` (usuwa stuby). Tego wariantu
nie uruchamiałem (STATUS.md).

## Struktura

```
pl.aiwcorpo.mcp.gateway
├── auth/      C1: GatewayUser, 401 z resource_metadata, adresy RFC 9728
├── authz/     ToolAuthorizer (M1: grupy C9; M2: Cedar)
├── audit/     zdarzenia C8 na loggerze AUDIT
├── broker/    C4: BrokerClient, cache, credential.invalidated, token exchange, kontrola /v1/systems
├── config/    właściwości, beany, Spring Security, drugi connector Tomcat
├── jwt/       C2: klucze, wystawca, JWKS, rozdział portów, UUIDv7
├── mcp/       endpoint MCP (obie ery), sesje klientów, tools/list i tools/call, błędy C10
├── server/    konfiguracja statyczna serwerów (M1 w miejscu rejestru)
├── tls/       mTLS i sprawdzanie SAN serwera
└── upstream/  klient Streamable HTTP do serwerów, sesje per użytkownik
```

Miejsca na M2+: `ToolAuthorizer` (Cedar z `PolicyStore` z `mcp-policy-bundle`, `prv` z rewizji paczki),
`ServerRegistry` (rejestr C5/C6 z `mcp-manifest`), ścieżka `/v/<slug>/mcp` w `McpEndpoint`, `CallContext`
(pola `vs`/`vsc`).
