# mcp-gateway

MCP Gateway platformy MCP (strumień ws-05): jedyny punkt wejścia klientów AI. Uwierzytelnia użytkownika
tokenem z IdP (C1), pobiera z brokera poświadczenie użytkownika do systemu (C4), wystawia wewnętrzny JWT (C2)
i przekazuje wywołanie do serwera MCP po mTLS z nagłówkami C3. Każde wywołanie narzędzia zostawia zdarzenia
audytu C8 z jednym `requestId`.

Stan: kamień M2 (wirtualne serwery, API C5 dla BFF, jedna domena) na M1 (OAuth RS, broker, C2/C3, audyt).
Serwery z konfiguracji statycznej zamiast rejestru manifestów. Co działa, czego nie ma i odstępstwa:
[STATUS.md](STATUS.md). Kontrakty: `mcp-contracts` 2.2.5.

## Moduły

| Moduł | Zawartość |
| --- | --- |
| `gateway` | aplikacja Spring Boot 4.1.0 (Java 25), obraz `mcp-gateway:dev` |
| `test-server` | minimalny serwer MCP w miejscu `mcp-jira` oraz atrapa brokera (`TestBroker`: stały PAT per użytkownik, reszta dostaje `credential_required`) do testów i demo (mTLS, weryfikacja C2 według wektorów, C3 do mocka Jiry, audyt C8). To nie jest produkt; prawdziwy serwer powstaje z `mcp-server-template` (ws-04), prawdziwy broker to `mcp-credential-broker` |

## Co robi gateway w M1

- **Wejście (klient):** `POST /s/<serverId>/mcp`, Streamable HTTP, odpowiedzi `application/json`.
  - era 2026-07-28 (bezstanowa): `_meta` w każdym żądaniu, nagłówki `MCP-Protocol-Version`, `Mcp-Method`,
    `Mcp-Name` sprawdzane względem treści (`-32020`), nieobsługiwana wersja `-32022` z listą wersji,
    `server/discover`, wyniki z `resultType`;
  - era 2025-03-26 .. 2025-11-25: `initialize`, `Mcp-Session-Id` (Redis, `gw:session:*`, sesja związana z
    `sub` tokenu; obcy `sub` -> 404 jak sesja nieznana), `DELETE` kończy sesję, `GET` -> 405;
  - metody: `tools/list`, `tools/call`, `ping`; nazwy narzędzi dla klienta `<system>__<tool>` (C5).
- **OAuth RS (C1):** JWT z JWKS IdP, `iss`, `aud` zawiera `mcp-gateway`, wymagane `sub`, `azp`,
  `preferred_username` (każde najwyżej 255 znaków, `sub` bez prefiksu `system:`), `iat`, czas życia
  `exp - iat` najwyżej 60 min; brak lub zły token -> `401` z `WWW-Authenticate: Bearer resource_metadata="..."`;
  dokument RFC 9728 pod `/.well-known/oauth-protected-resource/s/<serverId>/mcp`. Nic nie jest anonimowe poza
  metadanymi.
- **Autoryzacja (tymczasowa, grupy zamiast Cedar):** `READ_ONLY` wymaga grupy `mcp-<system>-read`, `UPDATE` grupy
  `mcp-<system>-write`, `DESTRUCTIVE` zawsze odmowa (brak potwierdzeń przed M3). Interfejs `ToolAuthorizer` dostanie
  implementację Cedar z `PolicyStore`. Narzędzie spoza konfiguracji jest ukryte i daje `not_found_or_denied`.
- **Poświadczenia (C4):** `POST /v1/credentials/resolve` po mTLS (certyfikat CN `mcp-gateway`, nazwa brokera
  z konfiguracji) z JWT C2 `aud=mcp-credential-broker` i `tool`; `409` -> `credential_required` z `connectUrl`;
  każde `5xx`, brak połączenia, timeout -> `upstream_unavailable`; `4xx` inne niż `409` i odpowiedź spoza C4
  (np. wartość poświadczenia spoza widocznego ASCII) -> `internal_error`, bez zapisu do cache. Serwer nie
  dostaje wywołania bez poświadczenia. Dla systemów `token-exchange` gateway wymienia token użytkownika w IdP
  na `aud=mcp-credential-broker` i wysyła go jako `subjectToken`.
- **Cache poświadczeń:** w pamięci, klucz (`sub`, system, scopes), najwyżej `min(cacheTtlSeconds, 60 s,
  expiresAt)`. Subskrypcja Redis `credential.invalidated` usuwa wpisy (sub, system) od razu. Dopóki subskrypcja
  nie jest potwierdzona (start, awaria Redis, reconnect), cache jest wyczyszczony i pomijany. TCP keepalive i
  `PING` co 5 s na połączeniu subskrypcji wykrywają połączenie półotwarte (bez zdarzenia rozłączenia).
- **Do serwera (C2, C3):** nowy JWT ES256 na każde żądanie HTTP (`exp - iat` = 30 s, `jti` UUIDv7),
  `tool` tylko przy `tools/call`; `grp` tylko grupy `mcp-*`; wariant użytkownika do `initialize`/`tools/list`
  (sesje są per użytkownik), wariant serwisowy tylko w `GET /v1/systems` brokera przy starcie. Nagłówki do
  serwera budowane od zera: `Authorization`, `X-Request-Id`, `X-MCP-Credential`, `X-MCP-Credential-Type`,
  `Mcp-Session-Id`, `MCP-Protocol-Version`; z żądania klienta nie jest kopiowany żaden nagłówek. Sesje do serwera
  mają klucz zawierający `sub`, nigdy nie są współdzielone; po `404` sesji gateway robi `initialize` ponownie.
  Certyfikat serwera musi mieć SAN `<serverId>.internal` niezależnie od adresu połączenia. Odpowiedź serwera
  (JSON albo SSE) czytana z twardym limitem bajtów (4 MiB) i jednym limitem czasu na nagłówki i ciało (30 s).
  Komunikat błędu JSON-RPC serwera nie trafia do klienta: gateway oddaje stały tekst dla kodu.
- **JWKS wewnętrzny:** `https://<nazwa TLS>:8443/.well-known/jwks.json`, dwa `kid` (aktywny i następny).
  Klucze z pliku JWKS (`MCP_INTERNAL_JWT_KEYS_FILE`, `MCP_INTERNAL_JWT_ACTIVE_KID`) albo, bez pliku, dwa klucze
  generowane przy starcie. `kid` z prefiksem `test-` i opublikowane klucze testowe `mcp-contracts`
  (`PublishedTestKeys`) są odrzucane przy starcie.
- **Audyt C8:** logger `AUDIT`, jedna linia JSON na zdarzenie na stdout; na każde `tools/call` zdarzenia
  `policy_decision` i `tool_call` (bez wartości argumentów, tylko `argsLength`). `requestId` (UUIDv7) wraca do
  klienta w `X-Request-Id`; `X-Request-Id` klienta trafia do `clientRequestId`, jeśli pasuje do wzorca.
- **Metryki:** `/actuator/prometheus` (tylko port wewnętrzny, tylko z certyfikatem klienta o CN z `MCP_METRICS_CLIENT_CNS`; domyślnie nikt): `mcp_gateway_tool_calls_total`,
  `mcp_gateway_tool_call_duration_seconds`, `mcp_gateway_credential_cache_total`,
  `mcp_gateway_broker_resolve_total`, `mcp_gateway_requests_total`.

Porty: `8080` (klienci MCP) i `8443` (TLS z certyfikatem gateway'a: JWKS, `/actuator/health`,
`/actuator/prometheus`). Port wewnętrzny nie obsługuje ścieżek MCP, port publiczny nie obsługuje JWKS ani
actuatora.

## Co dochodzi w M2

- **Wirtualne serwery (link, C5):** `POST/GET/DELETE /admin/v1/virtual-servers` i endpoint MCP
  `<publicBaseUrl>/v/<slug>/mcp` (obie ery protokołu, sesje legacy jak na `/s/`). Link to nazwa i lista narzędzi
  `<system>__<narzędzie>`; zapis w PostgreSQL (tabela `virtual_servers`, Flyway `V1`), slug unikalny globalnie
  (`409 slug_taken` także dla cudzego sluga). Link tylko zawęża (niezmiennik 5):
  - tworzenie: każde narzędzie musi być znane, włączone i dozwolone dla twórcy, inaczej `403 access_denied` i nic się
    nie zapisuje; `resourceDefaults` niepuste -> `400 resource_defaults_unsupported` (sprawdzane przed resztą ciała,
    nie-obiekt -> `invalid_request`), puste lub brak -> przyjęte i nigdy nie zwracane (CC-085);
  - użycie: link ma tylko właściciel; cudzy lub nieistniejący slug daje to samo `404` (także `DELETE` sesji), slug
    spoza wzorca `VirtualServerSlug` nie trafia do bazy; `tools/list` pokazuje tylko narzędzia linku, które
    użytkownik może teraz wywołać; `tools/call` spoza linku -> `not_found_or_denied`, narzędzie linku bez uprawnienia ->
    `access_denied` (decyzja z bieżącego tokenu, nie z chwili utworzenia linku); link do kilku serwerów łączy ich
    listy (padnięty serwer jest pomijany, chyba że padły wszystkie);
  - claimy C2: każde żądanie przez link niesie `vs` = slug i `vsc` = `{}` (zawężanie zasobów uśpione); audyt C8 ma
    `virtualServer`.
- **API C5 dla BFF** (port wewnętrzny TLS, `/admin/v1/*`, nigdy na porcie publicznym): mTLS z certyfikatem o CN
  `mcp-portal-bff` (`gateway.admin.allowed-client-cns`) i token użytkownika z `aud=mcp-gateway-admin`; "bieżący
  użytkownik" to `sub` tego tokenu. Brak ważnego certyfikatu -> 401, certyfikat innego komponentu -> 403, token dla
  innego `aud` -> 401. Port wewnętrzny prosi o certyfikat klienta, ale go nie ocenia przy handshake
  (`AcceptAnyClientCertificate`): serwery i broker pobierają JWKS kontekstem SSL z własnym certyfikatem serverAuth, a
  kontrola celu certyfikatu w handshake zrywałaby to pobranie. Łańcuch (CA wewnętrzne, daty, EKU clientAuth) i CN
  sprawdza `AdminClientCertificateFilter` tylko dla `/admin/v1`. Ostrzeżenie Tomcata przy starcie o braku
  post-handshake authentication w TLS 1.3 jest oczekiwane: certyfikat jest żądany w pierwszym handshake, renegocjacja
  nie jest potrzebna.
  `X-Request-Id` BFF (UUIDv7) wraca w odpowiedzi, inny jest zastępowany. Odpowiedzi mają `Cache-Control: no-store`.
- **Katalog** `GET /admin/v1/catalog`: serwery i narzędzia z konfiguracji z polami C5: `title` (CC-082),
  `description`, `risk`, `action`, `access` i `requiredEntitlements` z polityki, `disabled` (serwer wyłączony,
  narzędzie wyłączone albo DESTRUCTIVE do czasu potwierdzeń; zgodnie z `tool_disabled` przy wywołaniu),
  `requiresConfirmation` (DESTRUCTIVE). Pola `credential`, `connection`, `status` i `actions` należą do katalogu
  portalu (C12): składa je BFF z C5, C4 `GET /v1/systems` i `GET /v1/connections`.
- **`credential_required` (C10)**: `connectUrl` = `<publicBaseUrl>/connections?system=<system>`; adres brokera z
  odpowiedzi 409 jest sprawdzany, ale nie przekazywany klientowi.
- **Jedna domena (CC-089):** adres publiczny (`MCP_PUBLIC_URL`, wymagany) jest jedynym źródłem `resource_metadata`,
  `resource` w RFC 9728, `url` linków i `connectUrl`; nagłówki `Host`, `X-Forwarded-*` i `Forwarded` nie mają wpływu.
  Metadane RFC 9728 leżą pod `/.well-known/oauth-protected-resource` i `.../s/<serverId>/mcp`, `.../v/<slug>/mcp`
  (inne ścieżki pod tym prefiksem: 404). Na każdej odpowiedzi portu publicznego, błędy i błędy kontenera
  (nieprawidłowe żądanie HTTP) też, są `X-Content-Type-Options: nosniff` i `Content-Security-Policy: default-src
  'none'; sandbox`; nigdy `Set-Cookie`; `Cookie` klienta jest ukrywany przed aplikacją (do serwera i brokera i tak
  idą nagłówki budowane od zera); odpowiedzi to `application/json` także przy `Accept: text/html`. Reverse proxy
  (ws-01) dokłada te same nagłówki i usuwa `Cookie` na `/s/`, `/v/` i `/.well-known/oauth-protected-resource*`.
- **Serwery:** konfiguracja statyczna wszystkich pięciu systemów (`application.yml`, narzędzia i ryzyko z ws-04);
  `enabled`, `version`, `title`, `description`, `action` i `disabled` per narzędzie. Autoryzacja nadal grupami
  `mcp-<system>-read|write` (Cedar i paczka polityk nie weszły do M2, STATUS.md).

## Konfiguracja

Zmienne środowiska (nazwy z `mcp-platform-dev`, usługa `mcp-gateway` profilu `full`); pełna lista w
`gateway/src/main/resources/application.yml`.

| Zmienna | Znaczenie |
| --- | --- |
| `MCP_OIDC_ISSUER`, `MCP_OIDC_JWKS_URI`, `MCP_OIDC_AUDIENCE` | C1: oczekiwany `iss`, JWKS IdP, audience (domyślnie `mcp-gateway`) |
| `MCP_OIDC_AUTHORIZATION_SERVER` | serwer autoryzacji w RFC 9728; domyślnie `MCP_OIDC_ISSUER` |
| `MCP_OIDC_TOKEN_URI`, `MCP_OIDC_CLIENT_ID`, `MCP_OIDC_CLIENT_SECRET` | token exchange dla systemów `token-exchange` |
| `MCP_PUBLIC_URL` | wymagany: publiczny origin portalu i gateway'a (`https://...`, `http://` tylko z `MCP_ALLOW_PLAIN_HTTP`), bez ścieżki; źródło `resource_metadata`, `url` linków i `connectUrl` |
| `MCP_DB_URL`, `MCP_DB_USER`, `MCP_DB_PASSWORD` | PostgreSQL (baza `gateway`): linki; Flyway zakłada tabelę przy starcie, bez bazy gateway nie wstaje |
| `MCP_ADMIN_AUDIENCE`, `MCP_ADMIN_AUTHORIZED_PARTY` | C5: `aud` tokenu BFF (domyślnie `mcp-gateway-admin`, token z `aud` `mcp-gateway` jest odrzucany, a token MCP z `aud` admina też) i wymagane `azp` (domyślnie `mcp-portal-bff`) |
| `MCP_ADMIN_CLIENT_CNS`, `MCP_ADMIN_REGISTRY_CLIENT_CNS` | C5: CN certyfikatów klienta dla operacji BFF (domyślnie `mcp-portal-bff`) i dla zapisu rejestru (domyślnie `mcp-registry-ci`); przydział operacji do listy jest w kodzie wg `x-allowed-client-cn`, operacja spoza kontraktu to 403 dla każdego CN |
| `MCP_VIRTUAL_SERVERS_MAX_PER_USER` | limit linków na użytkownika (domyślnie 50); nadmiar to 409 `virtual_server_limit_reached` (zdarzenie audytu z powodem `virtual_server_limit`) |
| `MCP_METRICS_CLIENT_CNS` | CN certyfikatów klienta dla `/actuator/prometheus` (puste = nikt) |
| `MCP_SERVER_<SYSTEM>_MCP_URL`, `_ENABLED`, `_VERSION` | adres (`https`), wyłącznik i wersja serwera dla JIRA, CONFLUENCE, GITLAB, SERVICEDESK, OPENSEARCH; adresy domyślne `https://mcp-<system>.internal:8443/mcp`, dla Jiry `MCP_SERVER_JIRA_URL` + `/mcp` |
| `MCP_INTERNAL_PORT` | port wewnętrzny TLS, domyślnie `8443` |
| `MCP_INTERNAL_JWT_ISSUER` | `iss` C2, domyślnie `https://mcp-gateway.internal` |
| `MCP_INTERNAL_JWT_KEYS_FILE`, `MCP_INTERNAL_JWT_ACTIVE_KID` | prywatny JWKS (P-256) i aktywny `kid`; puste = klucze generowane |
| `MCP_TLS_KEYSTORE`, `MCP_TLS_TRUSTSTORE`, `MCP_TLS_STORE_PASSWORD` | PKCS12 gateway'a (CN `mcp-gateway`, serverAuth+clientAuth) i CA |
| `MCP_BROKER_URL`, `MCP_BROKER_TLS_NAME` | broker i nazwa w jego certyfikacie (CC-035) |
| `MCP_REDIS_HOST`, `MCP_REDIS_PORT`, `MCP_REDIS_USER`, `MCP_REDIS_PASSWORD`, `MCP_REDIS_KEY_PREFIX` | Redis (ACL `gateway`, `gw:*`, `credential.invalidated`) |
| `MCP_SERVER_JIRA_URL` albo `MCP_SERVER_JIRA_MCP_URL` | adres `mcp-jira`; do pierwszego dopisywane jest `/mcp` |
| `MCP_POLICY_REVISION` | `prv` w C2 do czasu paczki polityk, domyślnie `00000000000000-0000000` |
| `MCP_ALLOWED_ORIGINS` | dozwolone `Origin` (lista); żądanie (POST, GET, DELETE) z innym `Origin` -> 403, bez `Origin` przechodzi |
| `MCP_ALLOW_PLAIN_HTTP` | tylko dev: `http` dla endpointu tokenów IdP (token exchange); bez flagi token exchange jest wyłączony, broker i serwery zawsze `https` |

Konfiguracja statyczna serwera (M1, w miejscu rejestru C5) jest w `application.yml`:

```yaml
gateway:
  servers:
    mcp-jira:
      system: jira
      internal-url: https://mcp-jira.internal:8443/mcp
      credential: {required: true, accepted-types: [user-secret, user-oauth]}
      tools:
        get_issue: {risk: READ_ONLY, title: Pobranie zgłoszenia, description: Returns one Jira issue by key.}
        add_comment: {risk: UPDATE, title: Dodanie komentarza, description: Adds a comment to a Jira issue.}
```

`serverId` musi być `mcp-<system>`, adres tylko `https`, nazwy narzędzi według `ToolName` z kontraktu; błąd
konfiguracji zatrzymuje start.

## Budowanie i testy

Wymaga JDK 25 i Dockera (Testcontainers: Redis z ACL jak w `mcp-platform-dev` i PostgreSQL 18.6).

```bash
export JAVA_HOME=/opt/homebrew/Cellar/openjdk@25/25.0.4.1/libexec/openjdk.jdk/Contents/Home
./mvnw -B install                                    # testy + jary obu modułów
docker build -t mcp-gateway:dev .
docker build -t mcp-gateway-test-server:dev -f test-server/Dockerfile .
```

| Test | Co sprawdza |
| --- | --- |
| `InternalJwtVerifierVectorTest` (test-server) | odbiorca C2 serwera testowego daje wynik i powód z każdego z 51 wektorów `test-vectors/jwt` (2.2.5) |
| `InternalTokenIssuerTest` | JWT gateway'a zgodny z `internal-jwt.schema.json` i przyjmowany przez odbiorcę; `tool` tylko przy `tools/call`; wariant serwisowy tylko na `GET /v1/systems`; odrzucenie kluczy `test-` i opublikowanych kluczy testowych |
| `CredentialCacheTest`, `CredentialServiceTest` | TTL, `expiresAt`, unieważnienie (sub, system), wyścig resolve/unieważnienie, pomijanie cache bez subskrypcji, typ poświadczenia, token exchange |
| `StreamableHttpClientTest` | limit bajtów odpowiedzi (SSE bez znaku nowej linii, JSON), limit czasu na milczący strumień SSE, wybór odpowiedzi z SSE po `id` |
| `GroupToolAuthorizerTest` | trzy poziomy ryzyka: `-read`, `-write`, DESTRUCTIVE zawsze odmowa |
| `AdminApiTest` | C5 przez mTLS: certyfikat BFF, innego komponentu, obcego CA, serwera (serverAuth) i brak; token dla złego `aud`; JWKS nadal pobierany przez klientów z dowolnym certyfikatem; katalog z polityki (odpowiedź zgodna ze schematem `Catalog`); tworzenie, lista, usuwanie linku; 409 `slug_taken`; cudzy link nie do usunięcia; 403 dla narzędzia ponad uprawnienia (nic nie zapisane); 21 błędnych ciał -> 400; kolejność kontroli `resourceDefaults` |
| `ClientTokenAuditTest` | zdarzenie `authentication` z gateway'a dla każdego powodu odrzucenia tokenu C1, tylko pola ze schematu, treść tokenu ani claimy nie trafiają do zdarzenia ani logu, awaria JWKS -> 401 i zdarzenie `jwks_unavailable` (przez HTTP), `typ` inny niż `JWT` -> 401, brak zdarzeń poza `/s/*/mcp` i `/v/*/mcp` |
| `MissingTokenEventLimiterTest` | limit zdarzeń `missing_token` na sekundę, nadmiar liczony w metryce |
| `AuditVectorsTest` | wszystkie wektory `audit-events` 2.2.5 oceniane schematem C8 zgodnie z `expected.valid` |
| `VirtualServerMcpTest` | `/v/<slug>/mcp`: lista tylko z narzędzi linku (kilka serwerów, padnięty serwer pominięty), `vs` i puste `vsc` w JWT do serwera i w audycie, narzędzie spoza linku -> `not_found_or_denied`, utracone uprawnienie -> `access_denied` bez resolve i bez wywołania serwera, cudzy i nieistniejący slug -> identyczne 404 (POST, DELETE, obie ery), slugi spoza wzorca, usunięcie linku działa od razu, `connectUrl` z adresu publicznego |
| `PublicEdgeTest`, `PublicEdgeFilterTest` | nosniff, CSP, brak `Set-Cookie` i JSON na ponad 20 odpowiedziach (gniazdo surowe: błędy aplikacji i kontenera, `Accept: text/html`), `Cookie` klienta nie dociera do serwera ani brokera, metadane RFC 9728 na adresie publicznym mimo fałszywego `Host`/`X-Forwarded-*`, metadane tylko dla kształtów endpointów MCP, wyzwanie bez znaków z żądania |
| `ClientCertificateVerifierTest`, `PublicUrlsTest`, `ResourceMetadataTest`, `ServerRegistryTest`, `VirtualServerServiceTest` | łańcuch, daty i cel certyfikatu klienta; origin publiczny; kształty ścieżek metadanych; rozwiązywanie nazw narzędzi i walidacja konfiguracji; walidacja ciała linku, brak zapytań do bazy dla złych slugów, tylko właściciel |
| `GatewayIntegrationTest` | prawdziwy gateway z IdP, brokerem i serwerem testowym po mTLS: 401 + RFC 9728, sesje i ich właściciel, obie ery protokołu, nagłówki klienta nie docierają do serwera, `credential_required`, `upstream_unavailable` (503 i zerwane połączenie), unieważnienie <= 1 s, TTL, SAN serwera, JWKS tylko na porcie wewnętrznym, audyt zgodny ze schematem C8, brak sekretów w logach; DESTRUCTIVE i UPDATE bez `-write`, poświadczenie spoza ASCII (bez wartości w logu), odpowiedzi brokera spoza C4, wstrzymanie kontenera Redis (cache pomijany, powrót po subskrypcji), tokeny C1 za długie i z `sub` `system:`, limit 1 MiB, `Origin` |

## Uruchomienie lokalne w `mcp-platform-dev` (ws-01)

### Na hoście (sprawdzone 2026-10-28, porty 18700-18703)

Infrastruktura z `make up` (Keycloak, Redis, PostgreSQL, certyfikaty); gateway, atrapa brokera i serwer testowy jako
procesy na hoście, bez zmian w kontenerach środowiska. Gateway: `http://localhost:18700` (klienci MCP, metadane),
`https://localhost:18701` (JWKS C2, actuator, C5 z mTLS); serwer testowy `https://localhost:18702/mcp`; atrapa
brokera `https://localhost:18703`.

```bash
export JAVA_HOME=/opt/homebrew/Cellar/openjdk@25/25.0.4.1/libexec/openjdk.jdk/Contents/Home
./mvnw -B install -DskipTests
scripts/run-dev-host.sh &                       # gateway, PostgreSQL gateway-owa baza zakladana przez Flyway
scripts/run-test-server-host.sh &               # w miejscu mcp-jira
BROKER_PATS="alice=alice-pat" scripts/run-test-broker-host.sh &   # alice ma PAT, reszta credential_required
# tokeny: klienta MCP i tego samego uzytkownika wymieniony na aud=mcp-gateway-admin (jak robi BFF)
TOKEN=$(python3 ../mcp-platform-dev/scripts/mcpdev.py token alice)
ADMIN_TOKEN=$(python3 ../mcp-platform-dev/scripts/mcpdev.py exchange alice --audience mcp-gateway-admin --requester mcp-portal-bff)
TOKEN=$TOKEN ADMIN_TOKEN=$ADMIN_TOKEN scripts/m2-demo.sh      # katalog, link, 409, 400, tools/list i tools/call na linku
TOKEN=$TOKEN scripts/mcp-demo.sh http://localhost:18700       # przebieg M1 na /s/mcp-jira/mcp
```

Atrapa brokera zastępuje prawdziwy broker, bo ten sprawdza JWT C2 kluczami gateway'a, który z niego korzysta
(klucze są losowe przy każdym starcie, `MCP_INTERNAL_JWT_KEYS_FILE` je utrwala). Z prawdziwym brokerem: jego
`scripts/run-dev-host.sh` z `MCP_GATEWAY_JWKS_URI=https://localhost:18701/.well-known/jwks.json`,
`MCP_GATEWAY_TLS_NAME=localhost` i `MCP_BROKER_PORT` spoza portów compose; `MCP_BROKER_URL` gateway'a wskazuje go.
`scripts/mcp-demo.sh` wypisuje odpowiedzi i `X-Request-Id` każdego żądania, zdarzenia jednego żądania z kilku
komponentów zbiera `python3 ../mcp-platform-dev/scripts/mcpdev.py audit <requestId> --logs <plik>`.

### W compose (profil `full`)

Obraz `mcp-gateway:dev` pasuje do usługi `mcp-gateway`; w M2 potrzebuje `MCP_PUBLIC_URL` na origin proxy
(`http://localhost:${PROXY_PORT}`, nie port gateway'a), `MCP_DB_*` i adresów pozostałych serwerów
(`MCP_SERVER_<SYSTEM>_MCP_URL`, domyślne `https://mcp-<system>.internal:8443/mcp` zgadzają się z aliasami profilu
`m2`). Serwer testowy może zastąpić `mcp-jira` przez `MCP_JIRA_IMAGE=mcp-gateway-test-server:dev`. Tego wariantu
w M2 nie uruchamiałem (STATUS.md).

## Struktura

```
pl.aiwcorpo.mcp.gateway
├── admin/     C5: AdminController (katalog, linki), mTLS: ClientCertificateVerifier i filtr CN
├── auth/      C1: GatewayUser, 401 z resource_metadata, PublicUrls, adresy RFC 9728
├── authz/     ToolAuthorizer (grupy C9 zamiast Cedar)
├── edge/      jedna domena: PublicEdgeFilter, WellKnownGuard, błędy tylko JSON
├── virtual/   linki: VirtualServerStore (PostgreSQL), VirtualServerService
├── audit/     zdarzenia C8 na loggerze AUDIT
├── broker/    C4: BrokerClient, cache, credential.invalidated, token exchange, kontrola /v1/systems
├── config/    właściwości, beany, Spring Security, drugi connector Tomcat
├── jwt/       C2: klucze, wystawca, JWKS, rozdział portów, UUIDv7
├── mcp/       endpoint MCP (obie ery), sesje klientów, tools/list i tools/call, błędy C10
├── server/    konfiguracja statyczna serwerów (M1 w miejscu rejestru)
├── tls/       mTLS i sprawdzanie SAN serwera
└── upstream/  klient Streamable HTTP do serwerów, sesje per użytkownik
```

Miejsca na dalsze kamienie: `ToolAuthorizer` (Cedar z `PolicyStore` z `mcp-policy-bundle`, `prv` z rewizji
paczki), `ServerRegistry` (rejestr C5/C6 z `mcp-manifest` zamiast konfiguracji narzędzi), `vsc` w
`InternalTokenIssuer` (zawężanie zasobów, uśpione).

## Audyt odrzuconych tokenów: ryzyko zalewu

Zdarzenie `authentication` powstaje tylko dla `/s/<serwer>/mcp` i `/v/<slug>/mcp` (nie dla innych ścieżek ani `OPTIONS`). Żądania bez tokenu nic nie kosztują wołającego, dlatego `missing_token` ma limit 20 zdarzeń na sekundę na proces; nadmiar zwiększa `gateway_audit_authentication_suppressed_total` i nie trafia do C8. Odrzucone tokeny (zły podpis, wygasły) nie mają limitu: wymagają zdarzenia dla każdego odrzucenia, więc brzeg (nginx `limit_req` per adres) powinien ograniczać ich liczbę.
