# Status ws-05 (mcp-gateway)

Kamień: **M2** (fala z 2026-10-28) na kontraktach `mcp-contracts` **2.2.1**: wirtualne serwery, API C5 dla BFF
(katalog, linki), `credential_required` z linkiem do portalu, jedna domena (CC-089). Pod spodem M1 (OAuth RS,
broker, C2/C3, audyt, jeden serwer). M3 (potwierdzenia, zawężanie zasobów, `overrides`) i M4 nie są zaczęte.

## Kamienie pośrednie M2

| Kamień | Zakres | Commit |
| --- | --- | --- |
| K1 | kontrakty 2.2.1; serwery z metadanymi katalogu (`title`, `description`, `action`, `enabled`, `disabled`); PostgreSQL + Flyway; C5 `catalog` i `virtual-servers`; `/v/<slug>/mcp`; `vs`/`vsc` w C2; `connectUrl` z adresu publicznego; reguły jednej domeny (nosniff, CSP, JSON, bez cookies) | `33d3f98` |
| K2 | mTLS C5 (certyfikat klienta oceniany w filtrze, nie w handshake: regresja pobierania JWKS przez serwery); konfiguracja pięciu systemów; atrapa brokera, skrypty hosta na portach 18700-18703, demo na żywo z Keycloakiem, PostgreSQL i Redisem; README | `db8454b` |
| K3 | port wewnętrzny rozpoznawany po znormalizowanej ścieżce (`//admin/v1`, `/%61dmin/v1`), szersze testy negatywne ścieżek; mutacje testów (3 z 3 zabite) | `1aed158` |

## M2: zakres z zadania

| Punkt | Stan |
| --- | --- |
| 1. Kontrakty 2.2.1 | `pom.xml` 2.2.1, 51 wektorów JWT (odbiorca serwera testowego zna `server/discover`), schemat audytu C8 (`virtualServer`, `admin_change`), katalog i `VirtualServer*` walidowane schematami z OpenAPI C5 w testach. Zdarzenie `authentication` (2.1.0/2.1.1) jest dla odbiorców JWT (serwery, broker), gateway go nie emituje. `no-store` na odpowiedziach potwierdzeń: potwierdzenia to M3. Pivot 3.0.0 nietknięty |
| 2. Wirtualne serwery | CRUD, 409 `slug_taken`, filtr `tools/list` i `tools/call` do narzędzi linku i do uprawnień bieżącego tokenu, `vs`/`vsc` w C2, `resource_defaults_unsupported` (kolejność z README 2.2.1); link tylko dla właściciela |
| 3. Katalog C5 | `GET /admin/v1/catalog` z `title`, `disabled`, `requiresConfirmation`, `access`, `requiredEntitlements`; `enabled` serwera (CC-088) przez `disabled` wszystkich jego narzędzi. **Bez** `credential`, `connection`, `status`, `actions`: w kontrakcie to katalog portalu C12 (`PortalCatalogServer`), składany przez BFF z C5, C4 `GET /v1/systems` i `GET /v1/connections`; schemat C5 ma `additionalProperties: false`. `GET /admin/v1/registry/servers` (tam leży `RegistryServer.enabled`) nie jest zrobione |
| 4. `credential_required` | `connectUrl` = `<publicBaseUrl>/connections?system=<system>`, adres z konfiguracji; `connectUrl` z odpowiedzi brokera jest sprawdzany i nie przekazywany klientowi |
| 5. Jedna domena | RFC 9728 pod `/.well-known/oauth-protected-resource*` na adresie publicznym (tylko kształty endpointów MCP), tylko JSON, nosniff i CSP na każdej odpowiedzi portu publicznego (także błędy aplikacji i kontenera), brak `Set-Cookie`, `Cookie` ukryty przed aplikacją, C5 i JWKS na porcie wewnętrznym |
| 6. Testy | niżej |

### Testy

```
./mvnw -B install
test-server: Tests run: 51, Failures: 0, Errors: 0   (InternalJwtVerifierVectorTest, wszystkie wektory C2 2.2.1)
gateway:     Tests run: 107, Failures: 0, Errors: 0
  GatewayIntegrationTest 30, VirtualServerMcpTest 11, AdminApiTest 11, PublicEdgeTest 8, InternalTokenIssuerTest 8,
  VirtualServerServiceTest 6, CredentialCacheTest 6, GroupToolAuthorizerTest 5, CredentialServiceTest 4,
  StreamableHttpClientTest 4, ClientCertificateVerifierTest 4, ServerRegistryTest 3, ResourceMetadataTest 3,
  PublicUrlsTest 2, PublicEdgeFilterTest 2
```

Scenariusze negatywne z zadania i gdzie siedzą: link z narzędziem ponad uprawnienia twórcy (`AdminApiTest.aLinkNeverReachesBeyondTheCreatorsRights`,
`VirtualServerServiceTest`), utrata uprawnienia po utworzeniu (`VirtualServerMcpTest.linkNeverKeepsAPermissionTheUserLost`:
`access_denied`, zero wywołań brokera i serwera), cudzy slug (`someoneElsesSlugIsNotFoundForEveryMethodAndEra`: to samo
404 co dla nieistniejącego, POST/DELETE, obie ery), slug spoza wzorca (`slugsOutsideThePatternAreNotFound...` i
`VirtualServerServiceTest`: zapytanie do bazy nie jest wykonywane), narzędzie spoza linku (`toolOutsideTheLink...`:
`tool_disabled`), `Cookie` od klienta (`PublicEdgeTest.clientCookies...`, `PublicEdgeFilterTest`). Mutacje: link bez
filtra (5 testów czerwonych), link dostępny dla każdego (2), tworzenie bez sprawdzania uprawnień (2).

### Przebieg na hoście (2026-10-28, `scripts/m2-demo.sh`)

Prawdziwy Keycloak (tokeny `alice`: `claude-code` i wymiana na `aud=mcp-gateway-admin` jak robi BFF), PostgreSQL i Redis
z `mcp-platform-dev`, gateway na 18700/18701, serwer testowy w miejscu `mcp-jira` na 18702, atrapa brokera na 18703
(alice ma PAT, bob nie). Wywołania C5 z `curl` z certyfikatem `mcp-portal-bff`.

```
== catalog   mcp-jira 1.0.0 add_comment:granted search_issues:granted get_issue:granted transition_issue:granted
              mcp-servicedesk ... :denied   mcp-confluence ... create_page:denied   (+ gitlab, opensearch)
== create link m2-demo   {"slug":"m2-demo","url":"http://localhost:18700/v/m2-demo/mcp"} HTTP 201
== the same slug again   {"error":"slug_taken"} HTTP 409
== resourceDefaults      {"error":"resource_defaults_unsupported"} HTTP 400
== no token on the link  HTTP/1.1 401, nosniff, CSP, WWW-Authenticate: Bearer resource_metadata="http://localhost:18700/.well-known/oauth-protected-resource/v/m2-demo/mcp"
== tools/list on the link  ['jira__get_issue', 'jira__search_issues']
== tools/call jira__get_issue on the link  {"key":"ABC-1","summary":"Login page returns 500"}   (PAT z atrapy brokera, przez serwer testowy do mocka Jiry)
== a tool the user may call but the link does not name  {"error":"tool_disabled", ...}
== delete the link: HTTP 204; potem /v/m2-demo/mcp -> {"error":"not_found"}
bob (bez PAT) na /s/mcp-jira/mcp z Cookie: connectUrl http://localhost:18700/connections?system=jira, 0 wystąpień wartości cookie w logach trzech procesów
```

Nie sprawdzone: prawdziwy Claude Code na linku (brak klienta w tej sesji; kryterium M2 wymaga go w mcp-platform-dev),
nginx przed gateway'em (ws-01), prawdziwy broker z M2 (ws-06) na jego portach, kontenery w compose.

## Decyzje i odstępstwa M2

- **Certyfikaty klienta na porcie wewnętrznym.** Pierwsza wersja (`certificateVerification=optional` z truststore)
  zrywała handshake serwerom pobierającym JWKS z własnym certyfikatem serverAuth (host: `mcp-jira` -> `unknown
  certificate`). Teraz Tomcat prosi o certyfikat i przyjmuje każdy (`AcceptAnyClientCertificate`, handshake dowodzi
  posiadania klucza), a `ClientCertificateVerifier` w `AdminClientCertificateFilter` sprawdza łańcuch do CA wewnętrznego
  (PKIX), daty, EKU clientAuth i CN, tylko dla `/admin/v1`. Skutek: certyfikat obcego CA lub bez clientAuth daje 401 z JSON,
  nie zerwanie połączenia. Tomcat ostrzega przy starcie o braku PHA w TLS 1.3 (zignorowane, bez renegocjacji).
- **Tożsamość klienta mTLS (przegląd bezpieczeństwa, MEDIUM):** jedyne miejsce w gateway'u, które rozpoznaje klienta po
  certyfikacie, to `AdminClientCertificateFilter`. Nazwa to jedyny CN podmiotu; podmiot z kilkoma CN albo RDN wielowartościowym
  jest odrzucany (403), a gdy certyfikat ma SAN DNS, jeden z nich musi być `<CN>` lub `<CN>.internal` (CC-035). Testy: dwa CN,
  CN w innej kolejności, SAN innego komponentu. Certyfikaty dev klientów mają SAN `<nazwa>`, więc przechodzą.
- **DESTRUCTIVE w katalogu:** `access: denied`, `disabled: true`, `requiresConfirmation: true`, `requiredEntitlements`
  `mcp-<system>-destructive`, bo wywołanie jest `tool_disabled` do M3 (brak potwierdzeń).
- **Narzędzie spoza linku** (znane z konfiguracji, ale nie w linku) i narzędzie spoza konfiguracji: ten sam wynik
  `tool_disabled`, audyt `deny`/`tool_disabled`. Kontrakt C10 nie ma kodu "nie ma tego w linku" (propozycja niżej).
- **Link do kilku serwerów:** padnięty serwer jest pomijany w `tools/list`; błąd tylko gdy padły wszystkie.
- **Rejestr:** serwery i narzędzia (ryzyko, tytuły, opisy) z `application.yml`; manifesty, `definitionHash` i
  zatwierdzanie (`PUT/GET /admin/v1/registry/...`) nie są zrobione. Konfiguracja pięciu systemów odpowiada narzędziom
  ws-04 (jira 4, confluence 3, gitlab 4, servicedesk 3, opensearch 2).
- **Polityka:** nadal grupy C9 (`GroupToolAuthorizer`), nie Cedar. Brak paczki polityk (ws-09), a `cedar-java` wymaga
  obrazu glibc zamiast Alpine; `prv` = `00000000000000-0000000` (CC-068 mówi, że od M2 gateway bez paczki nie wstaje:
  do domknięcia z Cedar).
- **Aktywność** (`GET /admin/v1/activity`), potwierdzenia, `policy/status`, rate limit: poza tym zadaniem.
- **Bez limitu liczby linków na użytkownika** i bez cache wyszukiwania linku (jedno zapytanie do PostgreSQL na żądanie
  `/v/`); przy 503 bazy klient dostaje błąd JSON-RPC `-32603` z HTTP 503. M4.
- **`MCP_PUBLIC_URL` jest wymagany** (wcześniej pusty = z `Host`), start bez niego się nie udaje.

## Odstępstwa i rzeczy niedokończone z M1 (aktualne)

- **Brak Spring AI MCP.** Spring AI 2.0.0 / MCP Java SDK 2.0.1 znają protokół do 2025-11-25 (brak 2026-07-28),
  a serwerowy transport SDK trzyma sesje i nagłówki poza kontrolą per użytkownik. Gateway ma własną, wąską
  implementację Streamable HTTP po obu stronach (JSON-RPC na Jacksonie, JDK `HttpClient`).
- **Do serwera tylko era legacy (2025-11-25 .. 2025-03-26).** Serwer w erze 2026-07-28 (bez `initialize`)
  nie jest obsługiwany; starter na Spring AI 2.0 i tak jej nie zna.
- **Nie przekazywane:** powiadomienia z SSE serwera (progress, logging), elicitation/sampling (gateway deklaruje wobec
  serwera puste capabilities), `notifications/*list_changed`, `subscriptions/listen`, anulowanie; odpowiedzi do
  klienta zawsze `application/json`. To reszta punktu 1 briefu.
- **Klucze C2 generowane przy starcie** (bez `MCP_INTERNAL_JWT_KEYS_FILE`): po restarcie gateway'a odbiorcy pobierają
  JWKS przy nieznanym `kid` (nie częściej niż co 10 s w atrapie brokera i serwerze testowym: po restarcie gateway'a
  zrestartuj je). Kilka instancji gateway'a wymaga wspólnego pliku kluczy (HA to M4).
- **Sesje do serwera w pamięci instancji** (sesje klientów są w Redis); inna instancja zrobi `initialize`.
- **JWKS IdP niedostępny** daje błąd uwierzytelnienia z Spring Security (nie mierzony; docelowo 503).
- **Serwer testowy:** `jti` w pamięci (nie Redis), bez manifestu i bez polityk; tylko do testów i demo. Atrapa brokera
  niczego nie przechowuje.
- **Obraz Alpine:** `cedar-java` nie ma bibliotek natywnych dla musl; przy Cedar obraz trzeba przenieść na glibc.
- **Zdarzenia audytu odrzuconych tokenów C1** (401): są tylko w metrykach `mcp.gateway.requests` i logu Spring Security,
  nie jako zdarzenie C8.

## Propozycje CC (do przeniesienia przez koordynatora do ws-00)

1. **C10/C5: kod dla "narzędzia nie ma w linku".** Dziś gateway używa `tool_disabled` ("administrator wyłączył") dla
   narzędzia poza linkiem, co jest mylące w audycie i w komunikacie. Opcje: `not_found_or_denied` (spójne z niezmiennikiem
   8) albo opis w C10, że `tool_disabled` obejmuje "niedostępne w tym endpoincie".
2. **C4 `CredentialRequired.connectUrl`:** gateway buduje link z `publicBaseUrl` i ignoruje wartość brokera (dwa źródła
   adresu portalu rozjeżdżają się w dev: broker `MCP_PORTAL_URL`, gateway `MCP_PUBLIC_URL`). Zapis w C4: pole
   informacyjne, albo usunięcie z odpowiedzi 409.
3. **C5/README, port wewnętrzny:** dopisać, że `/admin/v1/*` i JWKS C2 są na jednym porcie TLS, a klienci JWKS mogą
   przedstawić certyfikat tylko serverAuth, więc cel certyfikatu klienta (clientAuth) wolno sprawdzać dopiero w warstwie
   aplikacji dla `/admin/v1`, nie w handshake. Bez tego ten sam błąd zrobi następna implementacja (broker, starter).
4. **C8: zdarzenie odrzuconego uwierzytelnienia po stronie gateway'a** (token C1): `authentication` z `component:
   gateway` i słownikiem `reason` dla C1 (`expired`, `wrong_audience`, `bad_signature`, ...); schemat 2.1.1 wymienia
   tylko powody JWT wewnętrznego i zakazuje pól z niezweryfikowanego tokenu, więc wystarczy rozszerzyć słownik.
5. Z M1 nadal otwarte: `prv` przed pierwszą paczką (CC-068 częściowo to adresuje), metody 2026-07-28 w regułach C2
   (CC-069 przyjęte, zaimplementowane w wektorach 2.1.0+).

## Czego potrzebują inni

- **ws-07 (BFF), C5 w skrócie.** Adres: wewnętrzny port TLS gateway'a (compose `https://mcp-gateway.internal:8443`, host
  `https://localhost:18701`), nazwa w certyfikacie `mcp-gateway.internal` (CC-035; na hoście SAN ma też `localhost`).
  Uwierzytelnienie: certyfikat klienta CN `mcp-portal-bff` z CA wewnętrznego (bez niego 401, inny CN 403) i token
  użytkownika wymieniony na `aud=mcp-gateway-admin` (claim `groups` jest w nim potrzebny, bo z niego wynika dostęp);
  "bieżący użytkownik" to `sub` tego tokenu. Ścieżki: `GET /admin/v1/catalog`, `GET|POST /admin/v1/virtual-servers`,
  `DELETE /admin/v1/virtual-servers/{slug}`. Odpowiedzi: 201 `{slug, url}` (`url` = `<publicBaseUrl gateway'a>/v/<slug>/mcp`),
  400 `invalid_request` | `resource_defaults_unsupported`, 401 `unauthenticated`, 403 `access_denied` (narzędzie
  nieznane, wyłączone albo bez uprawnienia; nic się nie zapisuje), 404 `not_found_or_denied` (DELETE cudzego lub
  nieistniejącego), 409 `slug_taken`, 503 `upstream_unavailable` (baza). Ciało błędu to `{"error": "..."}` bez `message`.
  `X-Request-Id` (UUIDv7) wraca w odpowiedzi; BFF powinien go przekazywać. Katalog C5 nie zawiera `credential`,
  `connection`, `status` ani `actions`: BFF składa je sam (tabela i wektory `catalog-actions/`); `url` serwerów `/s/`
  BFF buduje z własnego `publicBaseUrl`. `disabled: true` jest także dla każdego DESTRUCTIVE do M3. BFF wywołuje
  gateway po `https` z weryfikacją nazwy z konfiguracji, nie z adresu. Proces hosta gateway'a: `http://localhost:18700`
  (MCP), `https://localhost:18701` (C5); `scripts/run-dev-host.sh` + `run-test-server-host.sh` +
  `run-test-broker-host.sh` w `mcp-gateway` (token `alice` dla BFF: `mcpdev.py exchange alice --audience
  mcp-gateway-admin --requester mcp-portal-bff`).
- **ws-01 (`mcp-platform-dev`):** w usłudze `mcp-gateway`: `MCP_PUBLIC_URL=http://localhost:${PROXY_PORT}` (origin proxy,
  teraz jest `GATEWAY_PORT`, co daje `resource_metadata` i `connectUrl` obok proxy); `MCP_DB_*` już są; adresy serwerów
  `MCP_SERVER_<SYSTEM>_MCP_URL` mają domyślne `https://mcp-<system>.internal:8443/mcp` (zgodne z aliasami profilu `m2`),
  `MCP_SERVER_JIRA_URL` nadal wymagany. Gateway musi wejść na alias `mcp-gateway.internal:8443` (zastępuje
  `gateway-admin-mock`, który ma ten sam alias) z certyfikatem `mcp-gateway`, a BFF dostać certyfikat
  `mcp-portal-bff` i zaufanie do CA. Proxy: `/s/`, `/v/` i `/.well-known/oauth-protected-resource*` na port 8080 gateway'a,
  na tych trasach usuwa `Cookie` i dokłada `nosniff` oraz CSP `default-src 'none'; sandbox` (`add_header ... always`);
  gateway robi to samo sam, ale proxy jest w kontrakcie. Obraz zbudowany lokalnie: `mcp-gateway:m2-3cdc720` (drzewo `3cdc720`, kolejne commity tylko dokumentacja); nie uruchamiany w compose.
- **ws-06 (broker):** bez zmian; `connectUrl` z 409 jest ignorowany przez gateway (patrz CC 2). `GET /v1/systems` jest
  wołane wariantem serwisowym przy starcie dla wszystkich pięciu systemów (ostrzeżenie w logu, gdy broker zna mniej).
- **ws-04 / ws-02 (serwery, starter):** wywołania przez link niosą `vs` = slug i `vsc` = `{}` w JWT (wszystkie żądania
  HTTP danego wywołania, także `initialize`); odbiorca ma przyjąć puste `vsc` i zbudować puste `vsScopes`. Nazwy narzędzi
  w konfiguracji gateway'a odpowiadają stanowi serwerów z 2026-10-28; nowe narzędzie wymaga wpisu w `application.yml`
  (do czasu rejestru), inaczej jest ukryte.
- **ws-08 (web):** `POST /api/v1/virtual-servers` -> `url` z gateway'a; 409 `slug_taken` i 403 `access_denied` do
  pokazania w kreatorze; `title` narzędzi po polsku jest w konfiguracji gateway'a.
- **ws-09 (polityki):** paczka polityk i mapowanie `overrides` potrzebne, zanim Cedar zastąpi grupy (M3).

## Co zostało

Cedar `call` z paczką i `prv`; rejestr manifestów z `definitionHash` i zatwierdzaniem; `activity`; `policy/status`;
potwierdzenia (M3, pivot 3.0.0); rate limit i HA (M4); zdarzenia audytu C1; obraz glibc; test z prawdziwym Claude Code
i nginx w mcp-platform-dev.

---

# Kamień M1 (stan z 2026-10-27, bez zmian poza ścieżkami)

## M1: zrobione

| Punkt briefu | Stan |
| --- | --- |
| 1. MCP wejście i wyjście | `/s/mcp-jira/mcp`; klienci 2026-07-28 (bezstanowo, `_meta`, nagłówki `Mcp-Method`/`Mcp-Name` z kontrolą zgodności, `server/discover`, `-32020`/`-32022`) i 2025-03-26 .. 2025-11-25 (`initialize`, sesja w Redis związana z `sub`, `DELETE`, `GET` -> 405); do serwera Streamable HTTP 2025-11-25 po mTLS, odpowiedź JSON albo SSE |
| 2. OAuth RS (C1) | JWKS IdP z konfiguracji, `iss`, `aud` `mcp-gateway`, wymagane claimy; 401 z `resource_metadata`; RFC 9728 per ścieżka (filtr Spring Security 7 z nadpisanym `authorization_servers`); brak anonimowego dostępu |
| 8. Poświadczenia | `resolve` z JWT C2 (`tool`), `credential_required` z `connectUrl`, `upstream_unavailable`, `internal_error`; cache w pamięci <= `min(cacheTtlSeconds, 60 s, expiresAt)`; `credential.invalidated` usuwa wpisy; bez potwierdzonej subskrypcji cache wyłączony; token exchange dla systemów `token-exchange` |
| 9. Wewnętrzny JWT i C3 | nowy JWT na każde żądanie HTTP, `tool` tylko przy `tools/call` i `resolve`, wariant serwisowy tylko `GET /v1/systems`; nagłówki do serwera budowane od zera (nic z żądania klienta); sesje do serwera z kluczem zawierającym `sub`; SAN `<serverId>.internal` sprawdzany niezależnie od adresu |
| 11. Audyt i metryki | C8 `policy_decision` + `tool_call` na stdout (logger `AUDIT`), `requestId` UUIDv7 zwracany w `X-Request-Id`, `clientRequestId`; Prometheus na porcie wewnętrznym |
| Konfiguracja statyczna | `gateway.servers.mcp-jira`: system, `internal-url`, typy poświadczeń, narzędzia z `risk` |
| JWKS wewnętrzny | ES256, dwa `kid`, port TLS 8443; klucze z pliku albo generowane; `test-*` i opublikowane klucze testowe odrzucane (`PublishedTestKeys` z `mcp-cedar-entities` 2.0.2) |
| Obraz | `mcp-gateway:dev` (oraz `mcp-gateway-test-server:dev`), `eclipse-temurin:25-jre-alpine` przypięty digestem, użytkownik bez roota |

### Testy

```
./mvnw -B install
test-server: Tests run: 43, Failures: 0, Errors: 0   (InternalJwtVerifierVectorTest, wszystkie wektory C2 2.0.2)
gateway:     Tests run: 54, Failures: 0, Errors: 0
  GatewayIntegrationTest 30, InternalTokenIssuerTest 7, CredentialCacheTest 6, CredentialServiceTest 4,
  StreamableHttpClientTest 4, GroupToolAuthorizerTest 3
```

Punkty DoD briefu istotne dla M1:

| Punkt | Test |
| --- | --- |
| klient wysyła `X-MCP-Credential` / `X-PAT-Jira` -> nie dociera do serwera | `legacyClientListsAndCallsToolsWithInjectedCredential`: serwer widzi `Bearer alice-pat` z brokera, brak `x-pat-*`, `X-Request-Id` gateway'a, nie klienta; JWT klienta nie trafia do serwera |
| broker niedostępny -> `upstream_unavailable`, nigdy wywołanie bez poświadczenia | `brokerUnavailableMeansUpstreamUnavailableAndNoServerCall` (503), `brokerConnectionFailureMeansUpstreamUnavailable` (zerwane połączenie); serwer nie dostaje `tools/call` |
| `DELETE`/unieważnienie -> `credential_required` w <= 1 s, <= 60 s TTL | `invalidationEventDropsCachedCredentialWithinOneSecond`, `cachedCredentialExpiresWithItsTtl`, `invalidationOfAnotherUserOrSystemKeepsTheEntry`; z prawdziwym brokerem: zastąpienie PAT (`make pat`) publikuje zdarzenie i następne wywołanie idzie do brokera (niżej) |
| JWT z `tool` innym niż wywoływane narzędzie odrzucany przez serwer | `serverRejectsTokenWhoseToolDiffersFromTheCalledTool` (401, powód `tool_mismatch`); odbiorca serwera testowego przechodzi 43 wektory C2 |
| brak tokenu -> 401 + RFC 9728 | `missingTokenGets401WithResourceMetadata`, `tokenForAnotherAudienceOrUnknownSignerIsRejected` |

### Przebieg w `mcp-platform-dev` (2026-10-27)

Prawdziwy Keycloak, Redis z ACL `gateway`, OpenBao, mock Jiry; prawdziwy broker (`mcp-credential-broker`
5a5dbb4, `scripts/run-dev-host.sh` z `MCP_GATEWAY_JWKS_URI` tego gateway'a, bez kluczy testowych); gateway i
serwer testowy na hoście (`scripts/run-dev-host.sh`, `scripts/run-test-server-host.sh`). Token z `make token
USER=alice` (authorization code + PKCE klienta `claude-code`).

```
$ make pat USER=alice SYSTEM=jira BROKER_URL=https://localhost:18100
{"httpStatus": 200, "status": "connected", "backendUser": "alice", "expiresAt": null}
$ TOKEN=... scripts/mcp-demo.sh
== no token
HTTP/1.1 401
WWW-Authenticate: Bearer resource_metadata="http://localhost:18000/.well-known/oauth-protected-resource/s/mcp-jira/mcp"
== legacy tools/list                       -> jira__get_issue, jira__search_issues
== legacy tools/call jira__get_issue ABC-1 (z podrobionym X-PAT-Jira i X-MCP-Credential)
{"result":{"content":[{"type":"text","text":"{\"key\":\"ABC-1\",\"summary\":\"Login page returns 500\"}"}],"isError":false}}
  X-Request-Id: 01a17e02-0639-78a1-83f6-05dba2a89cc4
== modern tools/call (2026-07-28)          -> to samo, "resultType":"complete"
mallory: tools/list -> [], tools/call -> access_denied (requiredEntitlements: mcp-jira-read)

$ python3 scripts/mcpdev.py audit 01a17e02-0639-78a1-83f6-05dba2a89cc4 --logs <gateway+broker+serwer>
2026-10-27T15:37:04.315Z   gateway  mcp-gateway            policy_decision      allow
2026-10-27T15:37:04.363Z   broker   mcp-credential-broker  credential_resolve   ok
2026-10-27T15:37:04.404120Z server  mcp-jira               tool_call            ok
2026-10-27T15:37:04.405Z   gateway  mcp-gateway            tool_call            allow
components with events: ['broker', 'gateway', 'server']; missing: none        (exit 0)

$ make jira-auth
 200 GET /rest/api/2/issue/ABC-1?fields=summary,status   PAT alice-pat
```

W logach trzech procesów 0 wystąpień `alice-pat`. Unieważnienie z prawdziwego brokera: dwa wywołania z cache (0
zdarzeń `credential_resolve` brokera), `make pat USER=alice` (broker publikuje `credential.invalidated` przy
zastąpieniu, CC-046), następne wywołanie -> 1 zdarzenie `credential_resolve`.

## Przegląd M1 (2026-10-27): znaleziska i poprawki

Przegląd bez kontekstu: 0 CRITICAL, 0 HIGH, 4 MEDIUM, 13 LOW, wszystkie bez zmiany kontraktu.

| Znalezisko | Status |
| --- | --- |
| MEDIUM-1 wartość poświadczenia ze znakiem > U+00FF trafia do logu (wyjątek JDK z wartością nagłówka) | poprawione: `BrokerClient` przyjmuje tylko widoczne ASCII (0x21-0x7E), inaczej `internal_error` bez zapisu do cache; `RuntimeException` z wywołania serwera łapany, logowana tylko klasa, `internal_error` z audytem; test `credentialOutsideVisibleAsciiIsRejectedAndNeverLogged` (log bez wartości) |
| MEDIUM-2 brak limitu czasu czytania ciała (SSE) | poprawione: jeden budżet `gateway.upstream.timeout` (30 s) na nagłówki i ciało, po nim strumień zamykany, `upstream_unavailable`; test z milczącym SSE |
| MEDIUM-3 brak testów DESTRUCTIVE i UPDATE z samym `-read` | poprawione: `delete_issue` DESTRUCTIVE w konfiguracji testowej (ukryte, `tool_disabled` także z `mcp-jira-destructive`), `add_comment` z samym `-read` -> `access_denied` z `mcp-jira-write`, bez resolve; `GroupToolAuthorizerTest` |
| MEDIUM-4 brak testu maszyny stanów `InvalidationListener`, połączenie półotwarte | poprawione: TCP keepalive, `PING` co `gateway.redis.health-interval` (5 s) na połączeniu subskrypcji, przy błędzie zamknięcie i nowa subskrypcja; test z `docker pause` kontenera Redis: `live` false, cache pusty i pomijany, po powrocie cache dopiero po subskrypcji |
| LOW-1 komunikat błędu JSON-RPC serwera do klienta | poprawione: stały tekst per kod (`-32700`, `-32600`, `-32601`, `-32602`, reszta) |
| LOW-2 odpowiedzi brokera i IdP bez limitu | poprawione: `BoundedInputStream` 64 KiB (resolve, `/v1/systems`, token exchange) |
| LOW-3 brak limitu sesji na `sub` | znane, M4 (razem z rate limit) |
| LOW-4 C1 bez `iat` i limitu czasu życia | poprawione: wymagany `iat`, `exp - iat` <= `gateway.oidc.max-token-lifetime` (60 min); sprawdzenie `typ` (Keycloak) nie, bo zależy od IdP (D4) |
| LOW-5 długości claimów C1, `sub` z `system:` | poprawione: 401 dla `sub`/`azp`/`preferred_username` > 255 znaków i `sub` z prefiksem `system:`; test |
| LOW-6 `Origin` tylko dla POST | poprawione: POST, GET, DELETE; test pozytywny i negatywny |
| LOW-7 metadane RFC 9728 z `Host` bez `MCP_PUBLIC_URL` | znane, M4 (wymóg `MCP_PUBLIC_URL` poza dev razem z konfiguracją produkcyjną) |
| LOW-8 `/actuator/prometheus` bez uwierzytelnienia na porcie wewnętrznym | znane, M4 (mTLS scrapera albo osobny port metryk) |
| LOW-9 token exchange po `http` | poprawione: `http` tylko z `MCP_ALLOW_PLAIN_HTTP=true` (dev); bez flagi token exchange wyłączony z ostrzeżeniem przy starcie |
| LOW-10 luki w audycie (zły `tools/call`, filtr `tools/list`) | zły `tools/call` -> `tool_call` z `errorCode: invalid_argument` (test); decyzje filtra `tools/list` bez zdarzeń (znane, M2 razem z Cedar) |
| LOW-11 README o 5xx brokera, brak testów ścieżek `internal_error` | poprawione: README zgodne z kodem (każde 5xx -> `upstream_unavailable`); test 401 i 200 bez `value` -> `internal_error` bez `tools/call` |
| LOW-12 wyciek połączeń pub/sub, trwałe wyłączenie cache po wyjątku | poprawione: połączenie zamykane po nieudanej subskrypcji; po wyjątku bez rozłączenia ponowna subskrypcja przywraca `live` |
| LOW-13 testy limitu 1 MiB, wzorzec `prv`, `tool` na `mcp-jira` | poprawione: test 413, `policy-revision` sprawdzany wzorcem przy starcie; test `tool` na prawdziwym `mcp-jira` należy do ws-10/ws-04 |
