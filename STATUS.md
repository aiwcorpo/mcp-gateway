# Status ws-05 (mcp-gateway)

Kamień: **M1** z briefu: punkty 1 (bez agregacji wielu serwerów), 2, 8, 9, 11; jeden serwer `mcp-jira` z
konfiguracją statyczną. Kontrakty: `mcp-contracts` 2.0.2. M2-M4 nie są zaczęte.

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
gateway:     Tests run: 42, Failures: 0, Errors: 0
  GatewayIntegrationTest 22, InternalTokenIssuerTest 7, CredentialCacheTest 6, CredentialServiceTest 4,
  StreamableHttpClientTest 3
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

## Odstępstwa i rzeczy niedokończone

- **Demo poza compose.** `make audit RID=` czyta logi kontenerów profilu `full`. Uruchomienie kontenerów
  gateway'a, brokera i serwera testowego wymaga zatrzymania stubów `broker-mock` i `gateway-admin-mock` (te same
  aliasy DNS); zatrzymanie współdzielonych kontenerów zostało zablokowane, więc demo przeszło na procesach hosta,
  a audyt tym samym narzędziem (`mcpdev.py audit --logs`). Obraz `mcp-gateway:dev` jest zbudowany, ale w
  compose go nie uruchamiałem. Do zrobienia przez koordynatora: `make up-full` z
  `MCP_JIRA_IMAGE=mcp-gateway-test-server:dev` (albo z prawdziwym `mcp-jira`), `make audit RID=<X-Request-Id>`.
- **Brak Spring AI MCP.** Spring AI 2.0.0 / MCP Java SDK 2.0.1 znają protokół do 2025-11-25 (brak 2026-07-28),
  a serwerowy transport SDK trzyma sesje i nagłówki poza kontrolą per użytkownik. Gateway ma własną, wąską
  implementację Streamable HTTP po obu stronach (JSON-RPC na Jacksonie, JDK `HttpClient`).
- **Do serwera tylko era legacy (2025-11-25 .. 2025-03-26).** Serwer w erze 2026-07-28 (bez `initialize`)
  nie jest obsługiwany; starter na Spring AI 2.0 i tak jej nie zna.
- **Nie przekazywane w M1:** powiadomienia z SSE serwera (progress, logging), elicitation/sampling (gateway
  deklaruje wobec serwera puste capabilities), `notifications/*list_changed`, `subscriptions/listen`,
  anulowanie; odpowiedzi do klienta zawsze `application/json`. To reszta punktu 1 briefu.
- **Autoryzacja tymczasowa:** grupy `mcp-<system>-read|write` zamiast Cedar (M2); `DESTRUCTIVE` zawsze
  `tool_disabled`. `policyRevision` w audycie pominięte; `prv` = `00000000000000-0000000` (propozycja CC).
- **Klucze C2 generowane przy starcie** (bez `MCP_INTERNAL_JWT_KEYS_FILE`): po restarcie odbiorcy muszą
  pobrać JWKS ponownie (broker i serwer testowy robią to przy nieznanym `kid`); kilka instancji gateway'a
  wymaga wspólnego pliku kluczy (HA to M4). Rotacja "nowy `kid` publikowany 24 h przed użyciem" wymaga pliku
  z dwoma kluczami i przełączenia `MCP_INTERNAL_JWT_ACTIVE_KID`.
- **Sesje do serwera w pamięci instancji** (sesje klientów są w Redis); inna instancja zrobi `initialize`.
- **PostgreSQL** nie jest używany (wirtualne serwery i aktywność od M2); autokonfiguracja DataSource wyłączona.
- **JWKS IdP niedostępny** daje błąd uwierzytelnienia z Spring Security (nie mierzony; docelowo 503).
- **Serwer testowy:** `jti` w pamięci (nie Redis), bez manifestu i bez polityk; tylko do testów i demo.
- **Obraz Alpine:** `cedar-java` nie ma bibliotek natywnych dla musl; w M1 nic nie wywołuje Cedar, w M2 obraz
  trzeba przenieść na bazę glibc (np. `eclipse-temurin:25-jre`).

## Propozycje zmian kontraktów

Dopisane na końcu `mcp-contracts/CONTRACT_CHANGES.md` (status `open`, numer `CC-???`):

1. `prv` przed załadowaniem pierwszej paczki polityk (C2).
2. Metody MCP 2026-07-28 (`server/discover`, `subscriptions/listen`, MRTR) w regułach `tool` i wariantu
   serwisowego C2; uwaga do C11 (elicitation URL w erze 2026-07-28).

## Czego potrzebują inni

- **ws-04 (`mcp-jira`) / ws-02 (starter):** endpoint `/mcp` (gateway dopisuje `/mcp` do `MCP_SERVER_JIRA_URL`
  albo bierze pełny `MCP_SERVER_JIRA_MCP_URL`); Streamable HTTP 2025-11-25, 2025-06-18 lub 2025-03-26 z
  `initialize` i `Mcp-Session-Id`; odpowiedź `tools/call` JSON albo SSE; sesja wiązana z `sub` JWT (gateway nigdy
  nie miesza użytkowników); wariant użytkownika JWT także dla `initialize`, `notifications/initialized`,
  `tools/list` i `DELETE` sesji; `tool` == `params.name` przy `tools/call`; nazwy narzędzi zgodne z
  konfiguracją statyczną gateway'a (`search_issues`, `get_issue`, `add_comment`, `transition_issue`), inne są
  ukryte; certyfikat z SAN `mcp-jira.internal`; JWKS `https://mcp-gateway.internal:8443/.well-known/jwks.json`;
  `kid` gateway'a w dev są generowane (`gw-<data>-<losowe>-a|b`), nie testowe.
- **ws-06 (broker):** bez zmian względem STATUS brokera; sprawdzone z commitem 5a5dbb4. Jeśli broker ma
  publikować `credential.invalidated` po `DELETE`, gateway już to obsługuje.
- **ws-01 (`mcp-platform-dev`):** w usłudze `mcp-gateway` wystarczają obecne zmienne; opcjonalnie
  `MCP_PUBLIC_URL=http://localhost:${GATEWAY_PORT}` (bez niej adres z nagłówka `Host`, co przy mapowaniu
  18000:8080 daje ten sam wynik). Do demo przed powstaniem `mcp-jira`: `MCP_JIRA_IMAGE=mcp-gateway-test-server:dev`.
  `make audit` mogłoby przyjmować `--logs`, żeby działało także dla komponentów na hoście (dziś tylko przez
  `scripts/mcpdev.py`).
