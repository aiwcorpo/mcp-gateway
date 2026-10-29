# Status ws-05 (mcp-gateway)

Kamień: **M4** (fala z 2026-10-29) na kontraktach `mcp-contracts` **4.1.0**. Pod spodem M3 (od "Kamienie pośrednie M3" niżej),
M2 i M1; wiersze zastąpione w M4 są oznaczone.

## Kamienie pośrednie M4

| Kamień | Zakres | Commit | Obraz |
| --- | --- | --- | --- |
| K1 | kontrakty 4.0.0; rejestr z przypinaniem definicji (CC-097, CC-133, CC-161, CC-162): certyfikat potoku `mcp-registry-ci-<serverId>`, `RegistryPlanner` (READ_ONLY zatwierdza commit, UPDATE/DESTRUCTIVE czeka), `approve` z 409/422, `tools/list` z zatwierdzonych definicji, TTL <= 60 s, `definition_changed`/`tool_not_served`, wpisy `source: server`, `upstream_unavailable` bez wołania serwera, start z nieprzechodzącym manifestem = serwer `enabled: false`; `environment_mismatch`, `credential_type_mismatch`; `context.credentialType`; klucze `dev-` tylko w trybie dev; stały tekst `not_found_or_denied`; paczki polityk na schemacie 4.0.0; poprawka z koordynatora (paczka "nie nowsza" nie jest błędem ERROR, ETag zapamiętany) | `a72782e` | - |
| K2 | `POST /admin/v1/users/{sub}/purge` (CN `mcp-offboarding`), retencja aktywności z konfiguracji, limity w Redisie (użytkownik, klient, narzędzie, DESTRUCTIVE osobno), C10 `rate_limited` i 429, audyt z agregacją | `8b953aa` | - |
| K3 | `403 exchange_denied` -> `access_denied`, `422 system_not_configured` -> `internal_error` z odrębną przyczyną, token-exchange bez `expiresAt` odrzucany, testy poświadczeń i `context.credentialType`, README i STATUS, obraz | `019d69a` | `m4-019d69a` (zastąpiony) |
| K3b | poprawki przeglądu Opus (niżej), kontrakty 4.0.1, 516 testów gateway'a | `23a49eb` | `m4-23a49eb` (glibc; po pełnym `./mvnw -B install`; kolejne commity zmieniają tylko STATUS) |
| K4 | kontrakty 4.1.0 (CC-165..CC-168): wyniki aktywności wg wektorów (63), typ z brokera musi należeć do zbioru typów systemu, limity fail-closed z ciałem wektora, podłoga z wpisem oczekującym i `riskLowered`, `acceptRiskLowering`, `risk_lowered_by_admin`, odmowa startu przy mieszanym zbiorze typów i reguła manifestu | patrz niżej | patrz niżej |

## M4: zakres z zadania

| Punkt | Stan |
| --- | --- |
| 1. Rejestr i przypinanie | `PUT` tylko z CN równym `mcp-registry-ci-<serverId>` ze ścieżki (`AdminClientCertificateFilter.Rule` rozwiązuje `{serverId}` w nazwie; inny CN 403 + `authentication`/`client_certificate_rejected`). `RegistryPlanner` (czysta funkcja, 9 testów) decyduje: READ_ONLY nowe/zmienione -> zatwierdzone (`definition_registered`), UPDATE/DESTRUCTIVE -> `pending_approval` (`ci`, `new`/`changed`, `pendingVersion` = wersja manifestu; `definition_submitted`), usunięte -> `tool_removed`, niższe ryzyko niż najwyższe zatwierdzone, wymagane w konfiguracji lub zatwierdzone wcześniej (podłoga) -> 422 `risk_lowered` bez zapisu, także po usunięciu i dodaniu. `approve`: 404, 409 `hash_mismatch`, 422 `risk_lowered`, audyt `definition_approved` z `sub` administratora i `definitionHash`. `definitionHash` liczony z ryzyka, akcji i `resourceRefs` zatwierdzonego wpisu oraz z `credential` manifestu, z którym wpis zatwierdzono (kolumna per narzędzie). `tools/list` klienta z zatwierdzonych definicji; odczyt serwera cache'owany per serwer do TTL (`definition-check-ttl`, start odmawia > 60 s); werdykt per narzędzie INTACT/CHANGED/NOT_SERVED; CHANGED zapisuje wpis `source: server` (wersja z `serverInfo.version`, a gdy to nie SemVer, wersja zatwierdzona), którego nie zastępuje wpis `ci`; wpis `server` znika, gdy serwer wraca do zatwierdzonej definicji i przy `PUT`. Odczyt nieudany: lista bierze ostatni odczyt (brak odczytu = błąd jak w M3), wywołanie `upstream_unavailable` bez wołania serwera. Start: `load()` sprawdza trzymany manifest tymi samymi regułami, porażka = `enabled: false` bez kasowania; `reloadChanged` co kilka sekund adoptuje stan innej instancji. Bootstrap tylko gdy `MCP_REGISTRY_BOOTSTRAP` (strażnik: tylko `devstack`), zatwierdza całość, insert-only |
| 2. Offboarding | `UserPurge`: linki (`DELETE ... RETURNING slug`), stan potwierdzeń i znacznik epoki spalenia w Redisie, sesje MCP przez indeks `gw:session:of:<sha256(sub)>` (konto Redis nie ma `SCAN`), cache poświadczeń i sesje do serwerów tej instancji. 204 zawsze (400 tylko dla `sub` dłuższego niż 255), 503 przy awarii bazy lub Redisu; jedno zdarzenie `admin_change`/`user_purged` zawsze, `virtual_server_change` na link. Retencja tabeli aktywności: `gateway.activity.retention` (domyślnie 30 d). Inne instancje czyszczą swój cache poświadczeń zdarzeniem `credential.invalidated` brokera albo po TTL <= 60 s |
| 3. Limity | `RateLimiter`: jeden skrypt EVAL sprawdza i zlicza atomowo (okno stałe od pierwszego żądania, klucze `gw:rl:{u,c,t}:<sha256>`); odrzucone nie zużywa pozostałych liczników; DESTRUCTIVE i pojedyncze narzędzia osobno; `tools/call` -> C10 `rate_limited`, reszta -> 429 (`RateLimitResponse`, wektory `gateway-authentication/rate-limited*` przechodzą). `RateLimitAuditThrottle`: jedno zdarzenie na (sub, powód) w odstępie. `ActivityCall.result` `rate_limited`, w grupie `denied` |
| 4. Poświadczenia | `credential.type` z konfiguracji -> `context.credentialType` w `CedarToolAuthorizer` zawsze, przed oceną; niejednoznaczna konfiguracja zatrzymuje start. `exchange_denied`, `system_not_configured`, `expiresAt` tokenu wymienionego. `credential_type_mismatch`: typ gateway'a musi być w `acceptedTypes` manifestu (nie wszystkie typy z konfiguracji: manifest Jiry przyjmuje tylko `user-secret`, a konfiguracja pozwala też na OAuth) |
| 5. Tryb dev | `SigningKeys` i `BundleVerifier.withDevstackProfile`: `dev-` tylko z profilem i `allow-test-keys`; test-server i jego `InternalJwtVerifier` znają `devstackProfile`; `environment: dev` odrzucany poza `devstack`; nowe powody C8 w kodzie (`definition_changed`, `tool_not_served`, `rate_limited_*`, `exchange_denied`, `system_not_configured`, `user_purged`) |

## Testy (stan po K3)

```
./mvnw -B install
test-server: 106 testów
gateway:     516 testów, 0 błędów (z 445 w M3 na 3.1.0)
  nowe/zmienione w M4: RegistryPlannerTest 9, RegistryServiceTest 15 (PostgreSQL), RegistryStoreTest 5, RegistryTest 13 (HTTP, mTLS),
  ManifestAcceptanceTest 6, OffboardingTest 4, RateLimitTest 7, CredentialOutcomesTest 3, CredentialTypeContextTest 2,
  GatewayAuthenticationVectorsTest 15 (z 429), PolicyServiceTest +2 (`dev-`, paczka nie nowsza), ServerRegistryTest +1
```

Wektory 4.0.0 dotyczące gateway'a: `gateway-authentication/` (15, w tym `rate-limited*`), `manifests/` (55), `policy-decisions/` gateway (28, z
`credentialType` ze skonfigurowanego typu), `jwt/` (60, w tym `dev-`), `audit-events/` (schema), `activity-calls/` (52, w tym `rate_limited`),
`tool-errors/` (stały tekst `not_found_or_denied`), `bundles/` (przez bibliotekę).

## Decyzje i odstępstwa M4

- **Wymagana grupa `mcp-platform-admin`** na liście rejestru, `pending` i `approve` (opis "Forbidden" w kontrakcie); wcześniej lista nie sprawdzała grupy.
- **Odczyt `tools/list` serwera jest wspólny dla użytkowników** (jeden na serwer w oknie TTL), czytany sesją i tokenem użytkownika, który akurat go odświeża. Zakładam, że serwer nie filtruje listy per użytkownik (starter 3.x nie filtruje); gdyby filtrował, narzędzia byłyby `tool_not_served`.
- **Podłoga ryzyka** (po przeglądzie): najwyższe ryzyko kiedykolwiek zgłoszone dla narzędzia, także we wpisie oczekującym; oczekujące DESTRUCTIVE zastąpione przez UPDATE to 422 `risk_lowered`. Ryzyko przyjęte przez człowieka (zmiana nazwy z obniżeniem) nietknięte.
- **`credential_type_mismatch` porównuje jeden typ** (`credential.type` systemu) z `acceptedTypes` manifestu. Konfiguracja gateway'a dla Jiry, GitLaba (obie dopuszczają dwa typy) ma jawne `type`: Jira `user-secret`, GitLab `user-oauth`. Dla GitLaba wartość `user-oauth` musi być w manifeście serwera (jest: `user-secret,user-oauth`). `context.credentialType` dla systemów, w których użytkownik wybiera typ, nie mówi więc, który typ naprawdę poszedł do serwera (kontrakt każe podać typ z konfiguracji).
- **Redis nie odpowiada -> limity odmawiają** (decyzja z 2026-10-29): C10 `upstream_unavailable` albo 503, WARN, licznik.
- **`exchange_denied` w aktywności** to wynik `denied_not_granted` (propozycja CC niżej).
- **Zmienne usunięte:** `MCP_ADMIN_REGISTRY_CLIENT_CNS` (CN potoku wynika z `serverId`). Nowe: `MCP_ADMIN_OFFBOARDING_CLIENT_CNS`, `MCP_REGISTRY_DEFINITION_CHECK_TTL`, `MCP_RATE_LIMIT_*`, `MCP_ACTIVITY_RETENTION`.
- **Migracja z M3:** Flyway V5 tworzy `registry_tools` i wypełnia ją z zapisanych manifestów (wszystko zatwierdzone w wersji manifestu).
- **4.1.0 (K4):** `PUT` poniżej podłogi nie jest już 422: narzędzie czeka jako `riskLowered` (migracja Flyway V6, kolumna `pending_risk_lowered`), `approve` przyjmuje `acceptRiskLowering` (nie-boolean to 400, nie-admin 403, MFA to sprawa BFF), podłoga spada do zatwierdzonego ryzyka, zdarzenie `risk_lowered_by_admin` zamiast `definition_approved`; ryzyko z konfiguracji dalej 422. `exchange_denied`: `tool_call` allow + `denied`. `credential_type_mismatch` sprawdza każdy typ ze zbioru systemu, więc domyślny `accepted-types` Jiry to samo `user-secret` (manifest serwera Jira przyjmuje tylko ten typ; OAuth dla Jiry wymaga zmiany serwera i konfiguracji). Poprzednie decyzje o podłodze i fail-closed zostają, przy czym przegląd Opus L8 jest zamknięty przez CC-166.
- **Przegląd Opus M4 (0 HIGH, 2 MEDIUM, 9 LOW), poprawki w kolejnym commicie:** M1 fail-closed; podłoga ryzyka od zgłoszenia; L1 numer generacji w `DefinitionGuard` (odczyt w locie podczas `approve`/`PUT` jest odrzucany i powtarzany, po 3 próbach `upstream_unavailable`); L2 `policy_decision` `deny`/`upstream_unavailable` przy nieudanym odczycie; L3 sesja i jej wpis w indeksie zapisywane jednym skryptem, sesje sprzed M4 unieważniane przy wdrożeniu (README, "Przejście z M3 na M4"); L5 wersja spoza SemVer to `0.0.0-invalid` (nie wersja zatwierdzona) i WARN; L6 walidacja konfiguracji limitów przy starcie; L7 ETag nie jest zapamiętywany po `bad_signature` (poprawiona paczka pod tym samym wskaźnikiem zostanie pobrana), ERROR raz na rewizję i powód, potem DEBUG; L9 usunięte 4-argumentowe `evaluate`. **L4** (wiele instancji): `purge` czyści cache poświadczeń i sesje do serwerów tylko instancji, która go dostała; pozostałe czekają na `credential.invalidated` z brokera albo TTL <= 60 s, a offboarding woła broker i gateway w dowolnej kolejności, więc okno wynosi do 60 s. **L8** (`credential_type_mismatch` porównuje jeden typ): decyzja człowieka, typ z konfiguracji. **M2**: wyniki aktywności `rate_limited_*`, `definition_changed`, `tool_not_served`, `exchange_denied` mapuję na `denied` (`rate_limited`, `tool_disabled`, `denied_not_granted`); po kontrakcie 4.1.0 przejść na jego wektory. Kontrakty 4.0.1.
- **Niezrobione:** przeładowanie konfiguracji limitów bez restartu (klasa czyta ustawienia z dostawcy, ale nic go nie odświeża), `WAIT` przy stanie potwierdzeń w HA, test obciążeniowy, `curl` w obrazie.

## Czego potrzebuję od innych strumieni (M4)

- **ws-01:** certyfikaty klienta mTLS z CA wewnętrznego (EKU clientAuth, CN i SAN = CN): `mcp-registry-ci-mcp-jira`, `-mcp-confluence`, `-mcp-gitlab`, `-mcp-servicedesk`, `-mcp-opensearch` (po jednym na potok serwera; dawny `mcp-registry-ci` daje 403) i `mcp-offboarding`; wywołanie `purge` gateway'a w procesie offboardingu (powtórzone po wylogowaniu); usunięcie `MCP_ADMIN_REGISTRY_CLIENT_CNS`; w trybie dev klucze C2 z `kid` `dev-` w `MCP_INTERNAL_JWT_KEYS_FILE` (wymaga profilu `devstack`, obu zgód i `MCP_INTERNAL_JWT_ALLOW_TEST_KEYS=true`), klucze paczek `dev-` z `MCP_POLICY_ALLOW_TEST_KEYS=true`; bootstrap tylko w dev (`MCP_REGISTRY_BOOTSTRAP`), produkcja rejestruje przez potok. Serwery `devstack` powinny wysyłać `environment: dev`. Wolumen `/app/state` i Redis jak w M3 (Redis: gateway używa dodatkowo `SADD`, `SMEMBERS`, `EVAL`, `PEXPIRE`, `INCR`, które ACL z `redis/gateway.rules` już ma).
- **ws-04 (OpenSearch):** manifest z `acceptedTypes` zawierającym `token-exchange` zarejestrowany przed startem tego gateway'a, inaczej serwer jest po starcie `enabled: false`; Jira i Confluence mają `user-secret`, Service Desk `service-account`.
- **ws-09:** paczki na schemacie 4.0.0 z `credential-type.cedar`; gateway nie wymaga niczego więcej.
- **ws-07/ws-08:** lista rejestru, `pending` i `approve` wymagają grupy `mcp-platform-admin` w tokenie `aud=mcp-gateway-admin`.

## Propozycje CC (M4, do ws-00)

16. **`ActivityCall.result` dla `exchange_denied`:** referencja nie mówi; w gateway'u to `denied_not_granted` (grupa `denied`). Dopisać do `activity-calls.mjs` i wektorów albo wskazać inną wartość.
17. **Redis niedostępny a limity:** README ("Limity zapytań") nie mówi, czy żądanie przechodzi, czy jest odrzucane; gateway przepuszcza. Zapisać decyzję.
18. **Odczyt `tools/list` serwera jest globalny (TTL) czy per użytkownik:** README ("Rejestr...") mówi "odczyt odświeżany co TTL"; dopisać, że tools/list serwera nie zależy od użytkownika.
19. **Typ poświadczenia w kontekście Cedar dla systemów z dwoma typami (Jira, GitLab):** README mówi "z konfiguracji systemu"; dopisać, że to jeden typ na system, a nie typ użyty w wywołaniu.


## Kamienie pośrednie M3

| Kamień | Zakres | Commit | Obraz |
| --- | --- | --- | --- |
| K1 | kontrakty 3.0.1; 503 `upstream_unavailable` z `Retry-After` przy niedostępnym JWKS, także nieznany `kid` (CC-124, własny `IdpKeySet` z regułą "najwyżej jedno pobranie na odstęp", kolejność decyzji z README); powody odrzucenia bez parsowania komunikatów bibliotek (LOW-4: własne sprawdzenie klucza i podpisu, nazwane walidatory); audyt odrzuceń mTLS i tokenów BFF na C5, próbkowanie (CC-125); `virtual_server_change` (CC-116); osobne budżety `missing_token` i `malformed` | `dd2aa21` | `m3-dd2aa21` |
| K2 | potwierdzenia TOTP DESTRUCTIVE (C11): stan w Redis, `verify`, jedna oczekująca, "pierwsza wygrywa", `invalidate-codes`, C5 podgląd/`viewed`/`cancel`, fail-closed, utrata stanu; wektory `confirmation-binding/` (77), `totp/` (46, na atrapie brokera), `tool-errors/`; kontrakty 3.0.2 | `156e98e` | `m3-156e98e` |
| K3 | `/admin/v1/activity/calls` i `/activity` (CC-095, kursor HMAC, wektory `activity-calls/` 40 i `activity-cursor/` 9); rejestr: manifest, `definitionHash`, ukrycie niezgodnej definicji, `title` i zamknięty `inputSchema` (wektory `manifests/` 52); kontrakty 3.1.0 | `d04df49` | `m3-d04df49` |
| K4 | Cedar z podpisanych paczek (pull, podpis, monotoniczna rewizja, brak startu bez paczki, `prv`, `overrides`), ocena `call` z `refs` i `vsScopes` zamiast grup C9 (wektory `policy-decisions/` gw-*: 23); poprawki przeglądu rejestru (najwyższe zatwierdzone ryzyko, atomowa rejestracja, bootstrap tylko INSERT); obraz glibc; demo na żywo | `408c4e1` | `m3-408c4e1` |

## M3: zakres z zadania

| Punkt | Stan |
| --- | --- |
| 1. Kontrakty 3.0.1 -> 3.1.0 | 503 z `Retry-After` (domyślnie 10 s, 1..60) bez `WWW-Authenticate`, ciało i nagłówki z wektorów `gateway-authentication/` (13) i `-decision/` (12); 401 bez `error="invalid_token"` w nagłówku, ciało "Authentication required."; `client_certificate_rejected` (401 `unauthenticated`, 403 `access_denied`) bez danych z certyfikatu, jedno zdarzenie na adres źródłowy na interwał (domyślnie 1 min), reszta w `mcp_audit_authentication_suppressed_total{component="gateway",reason}`; tokeny BFF odrzucone na C5 z powodem tokenu; `virtual_server_change`; manifest: `title` i `inputSchema` według `ManifestRules` i schematu; `identity_mismatch` w gateway'u nie występował (nic do usunięcia) |
| 2. Potwierdzenia TOTP | kod w `confirmation_code`, pole dokładane do `inputSchema` w `tools/list` dla narzędzi DESTRUCTIVE (poza hashem); `ConfirmationRules` (port `scripts/lib/confirmation.mjs`) przechodzi wszystkie wektory `confirmation-binding/` razem z `auditReason`; `ConfirmationService` woła brokera (`GET /v1/authenticator`, `verify`, `invalidate-codes`; JWT użytkownika z `tool`, `X-Request-Id` = `rid`); mapowanie `ok`/`invalid`/`replayed`/`burned`/`locked`/`disabled`/`not_registered`/błąd; rezerwacja próby przed pytaniem brokera, zużycie przy `ok` jako compare-and-delete, anulowanie i zastąpienie w trakcie pytania wygrywają; testy na Redis: 12 równoległych złych kodów = 3 pytania do brokera, 6 równoległych dobrych = jedno wykonanie, 6 równoległych różnych operacji = jedna oczekująca. Poprawka z 3.0.1 (burn po potwierdzonym A także dla tej samej operacji) w wektorze `first-call-preview-viewed-confirmed-same-operation-burns`. Utrata stanu: brak rekordu = `confirmation_failed`; brak znacznika epoki (`gw:conf:epoch`) = przez 210 s pierwsze tworzenie na `sub` pali kody (błąd brokera = 503, nic nie powstaje). Niezaimplementowane: kanał elicitation URL / `InputRequiredResult` (tylko `confirmation_required` jako wynik narzędzia w obu erach) |
| 3. `/activity/calls` | jeden wiersz na wywołanie (zdarzenia w tabeli `activity_events`, 30 dni, `call_key` = `confirmationId` albo `requestId`, nie opuszcza gateway'a), `ActivityAggregator` przechodzi 21 wektorów agregacji i 19 kształtu wiersza; filtry `from`, `to`, `result` (grupy ok/denied/error/confirmation), `q`; kursor HMAC-SHA-256 (128 bitów, 15 min, związany z `sub`), wektory kursora; tylko własne wywołania; zdarzenia `policy_decision allow` nie są zapisywane |
| 4. Cedar | `PolicyService` + `BundleFetcher` + `PolicyStore` z `mcp-policy-bundle`: ETag, bez przekierowań, 16 MiB, podpis, schemat, rewizja rosnąca (CC-066: stan na dysku, rewizje minimalne), `overrides` co 5 s, oczekiwanie na `overrides` po restarcie, brak startu bez paczki (CC-068); `prv` = rewizja paczki głównej; grupy C9 zastąpione oceną Cedar `call` z `refs`, linkiem (`virtualServer`; `vsScopes` puste, bo zawężanie jest uśpione, CC-085); błąd oceny, błąd w diagnostyce i brak paczki = odmowa; argument nie będący identyfikatorem swojego typu = `invalid_argument`; reguły `destructive-requires-fresh-mfa` nie ma w paczkach testowych gateway'a ani w dev ws-09. Zadziałało z prawdziwą paczką dev ws-09 (`20261028201639-742561e`, główna i `overrides`) |
| 5. Rejestr w zakresie M3 | patrz "Decyzje i odstępstwa M3" |
| 6. LOW-4 | zamknięte: zakaz zależności od brzmienia komunikatów Nimbusa/Spring Security. Klucz (nieznany `kid`) i podpis (`bad_signature`) sprawdza `ClassifyingJwtDecoder` sam; `expired`/`not_yet_valid` to nazwane walidatory; tekst żadnej biblioteki nie decyduje o powodzie |
| 7. Limit zdarzeń | `missing_token` i `malformed` po 20/s na proces, osobne budżety; licznik `mcp_audit_authentication_suppressed_total{component,reason}` (starter ma `mcp_server_audit_...`), propozycja CC niżej |

## Testy (stan po K4)

```
./mvnw -B install
test-server: 103 testów (wektory JWT C2 57, wektory totp/ 46 na atrapie brokera)
gateway:     418 testów, 0 błędów
  nowe w M3: ConfirmationVectorsTest 77, ConfirmationFlowTest 16 (Redis, atrapa brokera z TOTP), ActivityVectorsTest 50,
  ActivityApiTest 6, ManifestVectorsTest 52, RegistryTest 6, RegistryStoreTest 6 (PostgreSQL, wyścigi), RegistryServiceTest 4,
  CedarDecisionVectorsTest 23, PolicyServiceTest 7, PolicyDistributionTest 5, IdpKeySetDecisionTest 13,
  GatewayAuthenticationVectorsTest 13, AdminAuthenticationAuditTest 6, AuthenticationEventLimiterTest 4, ToolErrorVectorsTest 2
```

Wektory uruchamiane z artefaktu `test-vectors` w wersji zależności (3.1.0). Jar 3.0.0 i 3.0.1 miał nieaktualne pliki wektorów (49);
w K1 i K2 były odfiltrowane listą, od 3.0.2 nie są (lista usunięta).

Mutacji w M3 nie robiłem. Test `parallelRightCodesExecuteOnce` znalazł prawdziwy błąd podczas pisania (równoległe złe kody wyczerpywały
licznik, zanim dobry kod wrócił od brokera, i dobry kod nie wykonywał narzędzia); poprawione w `ConfirmationRules.settle`.

## Przebieg na hoście (2026-10-28, `scripts/m3-demo.sh`)

Prawdziwy Keycloak (alice z grupą `mcp-jira-destructive`, wymiana tokenu BFF), PostgreSQL i Redis z `mcp-platform-dev`, prawdziwa
paczka dev ws-09 (główna i `overrides`) z serwera paczek ws-01, serwer testowy w miejscu `mcp-jira` (manifest pobrany i
zatwierdzony), atrapa brokera z ziarnem dev alice (kody z `mcpdev.py otp alice`). Wynik (skrót):

```
tools/list: jira__delete_issue True ^[0-9]{6}$
pierwsze wywołanie: confirmation_required (confirmationId, description, previewUrl, expiresAt), nic nie usunięte
podgląd BFF: tool, system, resource {Jira::Issue ABC-123, parent Jira::Project::ABC}, arguments; viewed 204
inna operacja DESTRUCTIVE przy otwartym podglądzie: confirmation_blocked (retryAfterSeconds 120)
token innego użytkownika: 404; zły kod: confirmation_failed; cancel 204 -> ponowienie confirmation_cancelled
nowa operacja, po 65 s dobry kod: {"deleted":"ABC-124"}; ten sam kod ponownie: confirmation_failed;
kolejna operacja z użytym kodem: confirmation_failed
activity/calls: confirmation_pending (ABC-125, 1 zły kod), confirmed (ABC-124), blocked_by_pending (ABC-999), cancelled (ABC-123, 1 zły kod)
```

Nie sprawdzone: prawdziwy broker M3 (w compose działa obraz M2 brokera; testowałem na atrapie, która liczy TOTP według tych samych
wektorów), proxy i Claude Code na `/v/<slug>/mcp`, start kontenera `mcp-gateway:m3-408c4e1` w compose (obraz zbudowany, `java -version`
działa, natywna biblioteka Cedar dla glibc niesprawdzona w kontenerze; macOS działa), UI portalu.

## Decyzje i odstępstwa M3

- **Rejestr bez zatwierdzania przez administratora.** Zatwierdzeniem jest rejestracja: `PUT /admin/v1/registry/servers/{serverId}`
  (CN `mcp-registry-ci`) zastępuje zatwierdzony zbiór całym manifestem, a serwer bez żadnego wiersza w `registry_servers` dostaje
  jednorazowo manifest, który sam serwuje (`INSERT ... ON CONFLICT DO NOTHING`, nigdy nie nadpisuje). C5 mówi, że nowe i zmienione
  narzędzia są `pending_approval`; to jest M4 (CC-097), więc wszystkie wpisy mają `status: approved`, brak `getPendingTool`/`approveTool`.
  Zamiast zatwierdzenia obniżenia ryzyka: odrzucenie `422 manifest_rejected`. Najwyższe kiedykolwiek zatwierdzone ryzyko per
  (serwer, narzędzie) leży w `registry_risk_floor` i nie znika z narzędziem; do tego minimalne ryzyko z konfiguracji. Zapisany manifest,
  który przestał być akceptowalny, zostawia serwer bez narzędzi (nie ma wtedy bootstrapu).
- **Tryb rejestru `required` jest domyślny**, a `static` (narzędzia z `application.yml`) tylko jawnie, per serwer (`manifest: static`) albo
  globalnie. Testy mają `static` dla serwerów bez manifestu i `required` dla `mcp-gitlab`.
- **Kontrola definicji przy wywołaniu:** wynik ostatniego sprawdzenia serwera żyje 30 s (`gateway.registry.definition-check-ttl`); po tym czasie
  wywołanie robi `tools/list` na serwerze. Zmiana opisu na serwerze: zniknięcie z `tools/list` natychmiast, odmowa wywołania najpóźniej po TTL.
- **Wywołanie wymaga grupy z paczki, nie z nazwy:** `requiredEntitlements` w `access_denied` i katalogu to nadal konwencja C9
  (`mcp-<system>-read|write|destructive`), informacyjna; przy `forbid` z polityki pole jest pominięte.
- **Powody w audycie spoza listy znanych wartości C8:** `link_scope` (narzędzie poza linkiem, jak w wektorach `activity-calls/`),
  `policy_unavailable`, `policy_error`, `invalid_argument`, `rate_limited` (zdarzenie `confirmation`). `policy_decision` z odmową ma teraz
  `outcome: denied` i `errorCode`.
- **Wywołania DESTRUCTIVE w M2 były `tool_disabled`** (odstępstwo z M2): zdjęte, `confirmation_required` zastępuje je.
- **Klucze Redis** (wszystkie pod `gw:`): `gw:conf:u:<sha256(sub)>` (cały stan użytkownika jako JSON, zapis skryptem EVAL), `gw:conf:epoch`,
  `gw:conf:eb:<epoka>:<sha256(sub)>`. Nie użyłem prefiksów `gw:confirm:pending|trace|count` z propozycji ws-01 (jeden klucz na użytkownika
  zamiast trzech rodzin); ACL gateway'a z `redis/gateway.rules` wystarcza (EVAL, bez SCRIPT).
- **`description` w `confirmation_required`:** `<narzędzie> (<system>): nazwa=wartość, ...`, wartości JSON, znaki zakazane (CC-121) jako `\uXXXX`,
  200 znaków na wartość, 50 argumentów, 1000 znaków łącznie. `resource.parent` tylko dla `Jira::Issue` (z klucza zgłoszenia).
- **Aktywność:** zapis zdarzeń jest synchroniczny; błąd zapisu zwiększa `gateway_activity_write_failures_total` i nie psuje wywołania. Wynik wiersza
  dla `tool_call` z `credential_required`/`rate_limited` to nazwany wynik, nie `error` (rozszerzenie względem referencji, wektory nie obejmują).
- **HA (M4):** rejestr, klucz kursora (`MCP_ACTIVITY_CURSOR_KEY`) i klucze C2 muszą być wspólne dla instancji; zatwierdzenia z innej instancji
  gateway widzi po restarcie.

## Poprawki po przeglądzie Opus M3 (0 CRITICAL/HIGH, 2 MEDIUM, 11 LOW)

| Id | Poprawka |
| --- | --- |
| M-1 | `ServerRegistry.apply` nie serwuje narzędzia zatwierdzonego poniżej minimum z konfiguracji ani `registry_risk_floor`; dotyczy `load()` po restarcie, rejestracji i przejęcia; testy `RegistryServiceTest` (konfiguracja DESTRUCTIVE, zapis READ_ONLY; podłoga) |
| M-2 | `PUT /admin/v1/registry/servers/{id}` ma osobny łańcuch security: sam mTLS z CN `mcp-registry-ci`, bez tokenu; inny CN 403, brak certyfikatu 401; reszta `/admin/v1` bez zmian. Bootstrap z manifestu serwera domyślnie wyłączony (`MCP_REGISTRY_BOOTSTRAP=false`), włączany w `run-dev-host.sh`; opisane jako zaufanie przy pierwszym kontakcie (L-1) |
| L-2 | README: wymagania wdrożeniowe stanu potwierdzeń (`noeviction`, `appendonly`, bez przywracania z kopii, bez failoveru bez synchronicznej replikacji) i czego epoka nie wykrywa |
| L-3 | TTL klucza względny (`PX`) z marginesem 30 s zamiast `PXAT` |
| L-4 | najwyżej 20 śladów zastąpionych operacji na użytkownika (`ConfirmationStateSizeTest`) |
| L-5 | `OperationDescription` liczy punkty kodowe (`OperationDescriptionTest`, emoji) |
| L-6 | zdarzenie `confirmation` z `reason`/`errorCode` `upstream_unavailable` dla każdej bramki, która nie dała rady (test); agregator traktuje je jak oczekiwanie |
| L-7 | `RegistryService.reloadChanged` co kilka sekund; `AlreadyThere` przejmuje zapisany wiersz |
| L-8 | osobne budżety 20/s także dla `alg_not_allowed`, `unknown_kid`, `bad_signature` |
| L-9 | `--enable-native-access=ALL-UNNAMED` w ENTRYPOINT, zdanie o `/tmp` i braku `curl` w README |
| L-10 | usunięte `policy-revision`/`MCP_POLICY_REVISION` i fallback `prv`; `state-dir` wymagany bez `allow-test-keys` (test) |
| L-11 | `confirmation_code` dodawany także do schematu bez `properties` (test) |
| ws-01/ws-09 | token z `azp` z `gateway.oidc.c5-only-clients` (domyślnie `mcp-portal-bff`) odrzucany na `/s/` i `/v/` (test); proces hosta pisze do własnego schematu `host_gateway` w bazie stosu (Flyway zakłada go; sprawdzone) |

Testy po poprawkach: gateway 427, test-server 103, 0 błędów. Nowe zdarzenie `reason` `upstream_unavailable` dopisać do słownika C8
(propozycja 12).

## Profil devstack (N-1 przeglądu środowiska dev)

`config/DevstackGuard`: relaksacje (klucze `test-*` JWT C2 i paczek, bootstrap manifestów, `static`, http dla `public-url`, JWKS, token
endpointu i paczek, `allow-plain-http`, brak `state-dir`) wymagają jedynego aktywnego profilu `devstack` i dwóch zgód
(`aiwcorpo.mcp.platform.devstack.acknowledged` oraz `MCP_DEVSTACK_ACKNOWLEDGED`); inaczej start jest odmówiony z listą wszystkich
problemów, zanim bean użyje relaksowanego ustawienia. WARN `event=devstack_profile` i gauge `mcp_gateway_devstack_active`. Testy
`DevstackGuardTest` (8): każda relaksacja bez profilu, z profilem i jedną zgodą, z profilem i obiema zgodami, same zgody bez profilu,
profil z innym profilem, produkcyjna konfiguracja bez profilu; `PolicyServiceTest`: klucz `test-*` odrzucony bez ustawienia. Testy
integracyjne działają na `@ActiveProfiles("devstack")`; zmienną `MCP_DEVSTACK_ACKNOWLEDGED` ustawia surefire jako prawdziwą zmienną procesu.
Zmienne dla ws-01 w README (sekcja "Profil devstack").

Poprawki po przeglądzie `0623849` (0 CRITICAL/HIGH, 3 MEDIUM, 6 LOW): M-1 zmienna zgody czytana tylko z środowiska procesu (`System.getenv()`
wstrzykiwane w testach jako mapa), README mówi wprost, że skopiowany cały blok compose przechodzi strażnika; M-2 strażnik jako
`ApplicationContextInitializer` (`META-INF/spring.factories`) plus bean z jawnym `@DependsOn("devstackGuard")` na beanach używających
relaksacji (`DevstackWiringTest` pada po usunięciu adnotacji), `PolicyService` znów sam wymaga `state-dir` poza devstack; M-3
`DevstackContextTest` (SpringApplication: bez profilu, sam profil, include, group, default; zero żądań do serwera paczek i JWKS,
odmowa z initializera); L-1 asercja powodu `test_key_not_allowed`; L-2 testy statycznego trybu, zbędny test usunięty; L-5 README;
L-6 `ConsentPackagingTest`. L-3: poza strażnikiem zostają `oidc.issuer`/`authorization-server` po http, puste `internal-jwt.keys-file`
(efemeryczne klucze C2) i puste `activity.cursor-key` (losowy klucz): to wygoda dev, w HA (M4) trzeba je ustawić. L-4: `devstack`
w gatewayu znaczy więcej niż w starterze (także http, `static`, bootstrap, brak `state-dir`), bo stos dev ich używa; relaksację
`state-dir` można usunąć, gdy żaden stos nie będzie jej potrzebował.

## Co potrzebuję od innych strumieni

- **ws-01:** wolumen na `/app/state` (stan ochrony przed cofnięciem paczek) i `MCP_POLICY_*` w usłudze `mcp-gateway` (klucze publiczne dev z
  `mcp-policies/keys/dev`, `MCP_POLICY_ALLOW_TEST_KEYS=true`), `MCP_REGISTRY_BOOTSTRAP` zostaje domyślnie włączony dla dev; `redis` z
  `appendonly yes` i `noeviction` (stan potwierdzeń); ewentualnie `MCP_ACTIVITY_CURSOR_KEY`. Obraz jest na glibc (`eclipse-temurin:25-jre`).
- **ws-06 (broker):** `GET /v1/authenticator`, `verify`, `invalidate-codes` z JWT użytkownika z `tool` i `X-Request-Id`; mój klient oczekuje `204` dla
  `invalidate-codes` i dla `verify` jednego z `ok|invalid|replayed|burned|locked|disabled|not_registered`.
- **ws-07/ws-08:** `viewed` po wyrenderowaniu podglądu, `cancel`, odpytywanie podglądu (404 po zastąpieniu); `X-Next-Cursor` przekazywany bez zmian.
- **ws-04 (serwery):** `GET /mcp-manifest` na korzeniu adresu serwera (gateway pobiera `<origin>/mcp-manifest` z JWT serwisowym) i narzędzie
  `delete_issue` (DESTRUCTIVE, `resourceRefs` `issueKey`) w demie.
- **ws-09:** paczka produkcyjna musi mieć `forbid` tylko tam, gdzie zamierzone; gateway wymaga `schemaVersion` zgodnego z 3.1.0 (ma).

## Propozycje CC (do ws-00)

10. **Nazwa licznika wspólna dla komponentów:** `mcp_audit_authentication_suppressed_total{component,reason}` (gateway: `component="gateway"`).
    Starter ma `mcp_server_audit_authentication_suppressed_total{reason}`, M2 gateway `gateway_audit_authentication_suppressed_total`. Kontrakt tego nie
    określa; do README (C8) razem z regułą "osobny budżet na powód dla `missing_token` i `malformed`, nadmiar tylko w liczniku".
11. **Wektory `gateway-authentication/`:** `resourcePath` to trasa (`/s/mcp-jira`), a gateway odsyła metadane zasobu równego adresowi endpointu
    (`/s/mcp-jira/mcp`, jak w M2 i RFC 9728). Doprecyzować w README albo wektorach.
12. **C8 `reason` i aktywność:** dopisać do słownika `link_scope` (zdarzenie `policy_decision` dla narzędzia poza linkiem), `policy_unavailable`,
    `policy_error`; `ActivityCall.result` dla `tool_call` ze `reason` `credential_required`/`rate_limited`; grupy filtra `result` (ok = ok;
    denied = `denied_*`, `tool_disabled`, `step_up_required`; error = `error`, `credential_required`, `rate_limited`; confirmation = reszta).
13. **C5 rejestr w M3:** zapis `PUT` jako zatwierdzenie do czasu CC-097 oraz `422` dla obniżenia ryzyka (także po usunięciu narzędzia), `getPendingTool`
    i `approveTool` nieobsługiwane (404) do M4. Doprecyzować `internalUrl` w manifeście: gateway porównuje host z adresem z konfiguracji albo z nazwą TLS
    `<serverId>.internal` i port.
14. **Znacznik epoki stanu potwierdzeń (README, "Utrata stanu"):** nazwać go w kontrakcie i opisać zachowanie wielu instancji (u mnie `gw:conf:epoch`
    w tym samym Redisie co stan, ważny 210 s po utracie), bo brak definicji grozi różnymi implementacjami u różnych instancji.
15. **Klient pobierania paczek** (CC-A ws-09) nadal po mojej stronie (`BundleFetcher`); jeśli wejdzie do `mcp-policy-bundle`, usunę własny.

Kamień: **M2** (zastąpiony przez M3 wyżej) na kontraktach `mcp-contracts` **2.2.5**: wirtualne serwery, API C5 dla BFF
(katalog, linki), `credential_required` z linkiem do portalu, jedna domena (CC-089). Pod spodem M1 (OAuth RS,
broker, C2/C3, audyt, jeden serwer). 

## Kamienie pośrednie M2

| Kamień | Zakres | Commit |
| --- | --- | --- |
| K1 | kontrakty 2.2.1; serwery z metadanymi katalogu (`title`, `description`, `action`, `enabled`, `disabled`); PostgreSQL + Flyway; C5 `catalog` i `virtual-servers`; `/v/<slug>/mcp`; `vs`/`vsc` w C2; `connectUrl` z adresu publicznego; reguły jednej domeny (nosniff, CSP, JSON, bez cookies) | `33d3f98` |
| K2 | mTLS C5 (certyfikat klienta oceniany w filtrze, nie w handshake: regresja pobierania JWKS przez serwery); konfiguracja pięciu systemów; atrapa brokera, skrypty hosta na portach 18700-18703, demo na żywo z Keycloakiem, PostgreSQL i Redisem; README | `db8454b` |
| K3 | port wewnętrzny rozpoznawany po znormalizowanej ścieżce (`//admin/v1`, `/%61dmin/v1`), szersze testy negatywne ścieżek; mutacje testów (3 z 3 zabite) | `1aed158` |
| K4 | poprawki przeglądu Opus (LOW 1-10, MEDIUM-1 odroczone do M3); obraz `mcp-gateway:m2-8dc1d7a` | `8dc1d7a` |
| K5 | kontrakty 2.2.5: CC-118 (`not_found_or_denied` dla narzędzia spoza linku), CC-119 (409 `virtual_server_limit_reached`), CC-120 (zdarzenie `authentication` z gateway'a dla odrzuconych tokenów C1) | `7ffa55d` |
| K7 | poprawki automatycznego przeglądu e4608ea: audyt `authentication` fail-closed (wyjątki tylko dla szumu), `InvalidationListener` traktuje zdarzenie nieznanego połączenia jako utratę subskrypcji | `d65088f` |
| K6 | poprawki przeglądu 7ffa55d: awaria JWKS -> 401 i zdarzenie, domyślne walidatory (`typ`, `cnf`) z powrotem, audyt `authentication` tylko dla `/s/*/mcp` i `/v/*/mcp` z limitem `missing_token`, stabilizacja testu Redis | `e4608ea` |

## M2: zakres z zadania

| Punkt | Stan |
| --- | --- |
| 1. Kontrakty 2.2.5 | `pom.xml` 2.2.5 (od K5; K1-K4 na 2.2.1), 51 wektorów JWT (odbiorca serwera testowego zna `server/discover`), schemat audytu C8 (`virtualServer`, `admin_change`), katalog i `VirtualServer*` walidowane schematami z OpenAPI C5 w testach. Zdarzenie `authentication` gateway emituje od K5 (CC-120): `ClassifyingJwtDecoder` + `McpAuthenticationEntryPoint`, powody `missing_token`, `malformed`, `alg_not_allowed`, `bad_signature`, `unknown_kid`, `wrong_issuer`, `wrong_audience`, `expired`, `not_yet_valid`, `invalid_claims`, `jwks_unavailable` (errorCode `upstream_unavailable`); tylko pola ze schematu, bez niczego z niezweryfikowanego tokenu; `X-Request-Id` w odpowiedzi 401. `replay_store_unavailable` nie dotyczy gateway'a (C1 nie ma sprawdzania `jti`). `client_certificate_rejected` nie jest emitowane: odrzucenia mTLS na C5 (`AdminClientCertificateFilter`, 401/403) i odrzucone tokeny BFF na `/admin/v1` nie zostawiają zdarzenia C8; to znane ograniczenie (propozycja CC 8). Audyt obejmuje każdą ścieżkę poza znanym szumem (`OPTIONS`, `/`, `/favicon.ico`, `/robots.txt`), bo lista dozwolonych ścieżek omijałaby warianty zapisu dopasowane przez łańcuch security; `missing_token` ma limit 20 zdarzeń na sekundę na proces, nadmiar tylko w metryce `gateway_audit_authentication_suppressed_total`. Awaria JWKS daje 401 (bez `invalid_token` w nagłówku, powód tylko w audycie), nie 503: propozycja CC 9. Walidatory `typ` i `cnf` z domyślnego zestawu Spring Security zostają (token `logout+jwt` -> 401 `invalid_claims`) `no-store` na odpowiedziach potwierdzeń: potwierdzenia to M3. Pivot 3.0.0 nietknięty |
| 2. Wirtualne serwery | CRUD, 409 `slug_taken`, filtr `tools/list` i `tools/call` do narzędzi linku i do uprawnień bieżącego tokenu, `vs`/`vsc` w C2, `resource_defaults_unsupported` (kolejność z README 2.2.1); link tylko dla właściciela |
| 3. Katalog C5 | `GET /admin/v1/catalog` z `title`, `disabled`, `requiresConfirmation`, `access`, `requiredEntitlements`; `enabled` serwera (CC-088) przez `disabled` wszystkich jego narzędzi. **Bez** `credential`, `connection`, `status`, `actions`: w kontrakcie to katalog portalu C12 (`PortalCatalogServer`), składany przez BFF z C5, C4 `GET /v1/systems` i `GET /v1/connections`; schemat C5 ma `additionalProperties: false`. `GET /admin/v1/registry/servers` (tam leży `RegistryServer.enabled`) nie jest zrobione |
| 4. `credential_required` | `connectUrl` = `<publicBaseUrl>/connections?system=<system>`, adres z konfiguracji; `connectUrl` z odpowiedzi brokera jest sprawdzany i nie przekazywany klientowi |
| 5. Jedna domena | RFC 9728 pod `/.well-known/oauth-protected-resource*` na adresie publicznym (tylko kształty endpointów MCP), tylko JSON, nosniff i CSP na każdej odpowiedzi portu publicznego (także błędy aplikacji i kontenera), brak `Set-Cookie`, `Cookie` ukryty przed aplikacją, C5 i JWKS na porcie wewnętrznym |
| 6. Testy | niżej |

### Testy

```
./mvnw -B install
test-server: Tests run: 51, Failures: 0, Errors: 0   (InternalJwtVerifierVectorTest, wszystkie wektory C2 2.2.5, bez zmian liczby)
gateway:     Tests run: 133, Failures: 0, Errors: 0   (stan po K7; po K4 było 120)
  GatewayIntegrationTest 32, AdminApiTest 16, VirtualServerMcpTest 12, PublicEdgeTest 8, InternalTokenIssuerTest 8,
  ClientTokenAuditTest 11, InvalidationListenerEventsTest 1, MissingTokenEventLimiterTest 1, AuditVectorsTest 1 (wszystkie wektory audit-events 2.2.5),
  VirtualServerServiceTest 7, CredentialCacheTest 6, GroupToolAuthorizerTest 5, ClientCertificateVerifierTest 5,
  CredentialServiceTest 4, StreamableHttpClientTest 4, InternalPortFilterTest 3, ServerRegistryTest 3,
  ResourceMetadataTest 3, PublicUrlsTest 2, PublicEdgeFilterTest 2
```

Scenariusze negatywne z zadania i gdzie siedzą: link z narzędziem ponad uprawnienia twórcy (`AdminApiTest.aLinkNeverReachesBeyondTheCreatorsRights`,
`VirtualServerServiceTest`), utrata uprawnienia po utworzeniu (`VirtualServerMcpTest.linkNeverKeepsAPermissionTheUserLost`:
`access_denied`, zero wywołań brokera i serwera), cudzy slug (`someoneElsesSlugIsNotFoundForEveryMethodAndEra`: to samo
404 co dla nieistniejącego, POST/DELETE, obie ery), slug spoza wzorca (`slugsOutsideThePatternAreNotFound...` i
`VirtualServerServiceTest`: zapytanie do bazy nie jest wykonywane), narzędzie spoza linku (`toolOutsideTheLink...`:
`not_found_or_denied`), `Cookie` od klienta (`PublicEdgeTest.clientCookies...`, `PublicEdgeFilterTest`). Mutacje: link bez
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
== a tool the user may call but the link does not name  {"error":"tool_disabled", ...}   (zapis z K4; od K5 (CC-118) wynik to not_found_or_denied, demo nie było przegnane na K5/K6)
== delete the link: HTTP 204; potem /v/m2-demo/mcp -> {"error":"not_found"}
bob (bez PAT) na /s/mcp-jira/mcp z Cookie: connectUrl http://localhost:18700/connections?system=jira, 0 wystąpień wartości cookie w logach trzech procesów
```

Nie sprawdzone: prawdziwy Claude Code na linku (brak klienta w tej sesji; kryterium M2 wymaga go w mcp-platform-dev),
nginx przed gateway'em (ws-01), prawdziwy broker z M2 (ws-06) na jego portach, kontenery w compose.

## Decyzje i odstępstwa M2

- **DESTRUCTIVE -> `tool_disabled` (odstępstwo od opisu C10 z 2.2.5).** Opis `ToolDisabled` po CC-118 mówi: tylko wyłączenie przez administratora albo definicja czekająca na zatwierdzenie. Narzędzie DESTRUCTIVE bez mechanizmu potwierdzeń (M3) nie pasuje do żadnego z tych przypadków; zostaje `tool_disabled` do M3, kiedy zastąpi je `confirmation_required`. Zachowanie jest też w katalogu (`disabled`). Bez zmiany kontraktu, do zdjęcia w M3.

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
  `not_found_or_denied`, audyt `deny`/`not_found_or_denied` (CC-118; `tool_disabled` tylko dla wyłączenia przez administratora).
- **Link do kilku serwerów:** padnięty serwer jest pomijany w `tools/list`; błąd tylko gdy padły wszystkie.
- **Rejestr:** serwery i narzędzia (ryzyko, tytuły, opisy) z `application.yml`; manifesty, `definitionHash` i
  zatwierdzanie (`PUT/GET /admin/v1/registry/...`) nie są zrobione. Konfiguracja pięciu systemów odpowiada narzędziom
  ws-04 (jira 4, confluence 3, gitlab 4, servicedesk 3, opensearch 2).
- **Polityka:** nadal grupy C9 (`GroupToolAuthorizer`), nie Cedar. Brak paczki polityk (ws-09), a `cedar-java` wymaga
  obrazu glibc zamiast Alpine; `prv` = `00000000000000-0000000` (CC-068 mówi, że od M2 gateway bez paczki nie wstaje:
  do domknięcia z Cedar).
- **Aktywność** (`GET /admin/v1/activity`), potwierdzenia, `policy/status`, rate limit: poza tym zadaniem.
- **Limit linków na użytkownika:** 50 (`MCP_VIRTUAL_SERVERS_MAX_PER_USER`), sprawdzany razem z INSERT pod blokadą
  doradczą PostgreSQL na właściciela. Bez cache wyszukiwania linku (jedno zapytanie do PostgreSQL na żądanie `/v/`);
  przy 503 bazy klient dostaje błąd JSON-RPC `-32603` z HTTP 503. Stronicowanie listy linków: nie (50 wierszy to górna granica).
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

1. **(przyjęte w 2.2.5 jako CC-118) C10/C5: kod dla "narzędzia nie ma w linku".** Do K4 gateway używał `tool_disabled` ("administrator wyłączył") dla
   narzędzia poza linkiem, co jest mylące w audycie i w komunikacie. Opcje: `not_found_or_denied` (spójne z niezmiennikiem
   8) albo opis w C10, że `tool_disabled` obejmuje "niedostępne w tym endpoincie".
2. **C4 `CredentialRequired.connectUrl`:** gateway buduje link z `publicBaseUrl` i ignoruje wartość brokera (dwa źródła
   adresu portalu rozjeżdżają się w dev: broker `MCP_PORTAL_URL`, gateway `MCP_PUBLIC_URL`). Zapis w C4: pole
   informacyjne, albo usunięcie z odpowiedzi 409.
3. **C5/README, port wewnętrzny:** dopisać, że `/admin/v1/*` i JWKS C2 są na jednym porcie TLS, a klienci JWKS mogą
   przedstawić certyfikat tylko serverAuth, więc cel certyfikatu klienta (clientAuth) wolno sprawdzać dopiero w warstwie
   aplikacji dla `/admin/v1`, nie w handshake. Bez tego ten sam błąd zrobi następna implementacja (broker, starter).
4. **(przyjęte w 2.2.5 jako CC-120) C8: zdarzenie odrzuconego uwierzytelnienia po stronie gateway'a** (token C1): `authentication` z `component:
   gateway` i słownikiem `reason` dla C1 (`expired`, `wrong_audience`, `bad_signature`, ...); schemat 2.1.1 wymienia
   tylko powody JWT wewnętrznego i zakazuje pól z niezweryfikowanego tokenu, więc wystarczy rozszerzyć słownik.
5. **(przyjęte w 2.2.5 jako CC-119) C5 `POST /virtual-servers`: odpowiedź na przekroczenie limitu linków.** Kontrakt zna tylko 409 `slug_taken` i 400
   `invalid_request`; gateway odpowiada 400 `invalid_request` (409 `slug_taken` kazałby kreatorowi szukać innego sluga w
   nieskończoność). Propozycja: 409 z kodem `virtual_server_limit_reached` (wzorzec `^[a-z][a-z0-9_]*$` pozwala) albo 429, plus
   limit w opisie operacji, żeby kreator pokazał "usuń nieużywany link".
6. **C8 `admin_change`: powody i lista narzędzi.** Gateway zapisuje `reason` ze słownika `vs_created`, `vs_deleted`,
   `slug_taken`, `not_granted`, `invalid_request`, `virtual_server_limit`, `not_found_or_denied`; schemat opisuje `reason` jako
   "known values" bez tych wpisów. Do dopisania w opisie pola. Pole z listą narzędzi linku (do pytania "kto utworzył link z
   gitlab__*") nie istnieje; opcja: `resource`-podobne pole `tools` w `admin_change`, ograniczone wzorcem `QualifiedToolName`.
8. **C8: audyt odrzuceń mTLS C5 i tokenów BFF.** `client_certificate_rejected` w opisie `reason` sugeruje emisję z gateway'a, a odrzucenia na `/admin/v1` i `/actuator/prometheus` nie są audytowane; ws-00 do decyzji, czy gateway ma je emitować i który komponent emituje `replay_store_unavailable` (wektor z `component: gateway`).
9. **C1: status przy niedostępnym JWKS.** Gateway odpowiada 401 z `resource_metadata` (jak przy każdym odrzuceniu, bez ujawniania powodu); przy awarii zależności 503 `upstream_unavailable` byłby dokładniejszy dla klienta. Do decyzji ws-00.
7. **C5/README: tożsamość scrapera metryk.** Kontrakt nie mówi, kto czyta `/actuator/prometheus` ani jakim certyfikatem. Gateway
   wymaga certyfikatu clientAuth z CA wewnętrznego i CN z `MCP_METRICS_CLIENT_CNS` (domyślnie pusta lista). Do ustalenia nazwa
   (np. `mcp-prometheus`) i wydanie certyfikatu w `gen-certs.sh` (ws-01), jeśli metryki mają być zbierane w M2.
8. Z M1 nadal otwarte: `prv` przed pierwszą paczką (CC-068 częściowo to adresuje), metody 2026-07-28 w regułach C2
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
  gateway robi to samo sam, ale proxy jest w kontrakcie. **Obraz dla ws-01: `mcp-gateway:m2-8dc1d7a`**, zbudowany lokalnie z jara po pełnym `./mvnw -B verify` na `8dc1d7a`
  (kod i testy; kolejne commity zmieniają tylko `STATUS.md`); poprzedni `m2-3cdc720` nie ma poprawek CN/SAN (94afc7d) ani K4.
  Nie uruchamiany w compose. Nowe zmienne (wszystkie z bezpiecznymi domyślnymi): `MCP_ADMIN_AUTHORIZED_PARTY` (`mcp-portal-bff`),
  `MCP_ADMIN_REGISTRY_CLIENT_CNS`, `MCP_VIRTUAL_SERVERS_MAX_PER_USER` (50), `MCP_METRICS_CLIENT_CNS` (puste: `/actuator/prometheus`
  odpowiada 401/403 każdemu; scraper potrzebuje certyfikatu clientAuth z CA wewnętrznego i jego CN na tej liście).
- **ws-06 (broker):** bez zmian; `connectUrl` z 409 jest ignorowany przez gateway (patrz CC 2). `GET /v1/systems` jest
  wołane wariantem serwisowym przy starcie dla wszystkich pięciu systemów (ostrzeżenie w logu, gdy broker zna mniej).
- **ws-04 / ws-02 (serwery, starter):** wywołania przez link niosą `vs` = slug i `vsc` = `{}` w JWT (wszystkie żądania
  HTTP danego wywołania, także `initialize`); odbiorca ma przyjąć puste `vsc` i zbudować puste `vsScopes`. Nazwy narzędzi
  w konfiguracji gateway'a odpowiadają stanowi serwerów z 2026-10-28; nowe narzędzie wymaga wpisu w `application.yml`
  (do czasu rejestru), inaczej jest ukryte.
- **ws-08 (web):** `POST /api/v1/virtual-servers` -> `url` z gateway'a; 409 `slug_taken` i 403 `access_denied` do
  pokazania w kreatorze; `title` narzędzi po polsku jest w konfiguracji gateway'a.
- **ws-09 (polityki):** paczka polityk i mapowanie `overrides` potrzebne, zanim Cedar zastąpi grupy (M3).

## Przegląd M2 (2026-10-28, Opus, 94afc7d): znaleziska i poprawki

Raport: scratchpad/review-gateway-M2.md. 0 CRITICAL, 0 HIGH, 1 MEDIUM, 10 LOW. Poprawki w `8dc1d7a`.

| Znalezisko | Status |
| --- | --- |
| MEDIUM-1 rejestr z `definitionHash`, Cedar `call` z paczką, `GET /admin/v1/activity`, odmowa startu bez paczki (CC-068) | **odroczone do M3** (decyzja koordynatora 2026-10-28, wiersz "Gateway M2 bez rejestru definicji" w tabeli decyzji STATUS.md planu; 00-overview: M3 = Cedar i dystrybucja paczek, M4 = przypinanie definicji). Nic z tego nie zaimplementowane. Do tego czasu: grupy C9 zamiast Cedar, `prv` = `00000000000000-0000000`, opisy narzędzi z konfiguracji (nie z `tools/list` serwera) idą do katalogu C5, ale `tools/list` na `/s/` i `/v/` nadal przekazuje definicję serwera bez porównania z zatwierdzoną; tanie zabezpieczenie z raportu (porównanie `description`/`inputSchema` z konfiguracją) nie zrobione, bo nie jest w zakresie decyzji |
| LOW-1 brak limitu linków na użytkownika | poprawione: 50 (konfigurowalne), 409 `virtual_server_limit_reached` (od K5, CC-119; wcześniej 400), zdarzenie audytu z powodem `virtual_server_limit`; testy: 50 + 1, limit per użytkownik, zwolnienie po DELETE, 16 równoległych POST przy 45 istniejących daje dokładnie 5 sukcesów |
| LOW-2 409 `slug_taken` zdradza cudzy slug | bez zmian: tak stanowi kontrakt C5 (zgłoszone w przeglądzie jako uwaga do kontraktu) |
| LOW-3 audyt `admin_change` | poprawione: powód `vs_created` / `vs_deleted` / `slug_taken` / `not_granted` / `invalid_request` / `virtual_server_limit` / `not_found_or_denied`, zdarzenia także dla 400, 403, 404, 409 (`deny`, `denied`, `errorCode` z C10 gdzie istnieje), slug w zdarzeniu tylko gdy zgodny ze wzorcem; testy sprawdzają każde zdarzenie schematem C8. Lista narzędzi linku w zdarzeniu: nie ma pola w C8 (propozycja CC 6) |
| LOW-4 `azp` i `aud` tokenu C5 | poprawione: C5 wymaga `azp` = `mcp-portal-bff` (`MCP_ADMIN_AUTHORIZED_PARTY`) i odrzuca `aud` zawierające `mcp-gateway`; `/s/` i `/v/` odrzucają `aud` z `mcp-gateway-admin`. Sprawdzone na żywym Keycloaku: wymieniony token BFF ma `azp: mcp-portal-bff` |
| LOW-5 jedna lista CN dla całego `/admin/v1` | poprawione: tabela operacja -> CN z `x-allowed-client-cn` (`AdminOperations`), operacja spoza tabeli to 403 dla każdego CN (także `/admin/v1/catalog/`, nieznany czasownik); zapis rejestru ma osobną listę `MCP_ADMIN_REGISTRY_CLIENT_CNS` |
| LOW-6 brak odwołań i wspólny truststore klientów C5 | bez zmian, znane, M4 (osobny truststore, krótkie certyfikaty albo lista numerów); nie było na liście poprawek |
| LOW-7 sesja do serwera wspólna dla `/s/` i linków | poprawione: klucz rozmowy zawiera cel (`serverId` albo `vs/<slug>`) w erze legacy i modern; DELETE sesji klienta zamyka sesje do serwera wszystkich endpointów; test sprawdza dwie różne sesje i `vs` w JWT |
| LOW-8 `/actuator/prometheus` bez uwierzytelnienia, 405 na porcie publicznym | poprawione: Prometheus wymaga certyfikatu klienta z CA wewnętrznego i CN z `MCP_METRICS_CLIENT_CNS` (domyślnie nikt: 401 bez certyfikatu, 403 z cudzym); port publiczny daje 404 dla ścieżek wewnętrznych (JWKS, `/actuator*`, `/admin/v1*`) niezależnie od metody |
| LOW-9 obraz bez poprawki CN/SAN | poprawione: `mcp-gateway:m2-8dc1d7a` z jara zbudowanego na `8dc1d7a` |
| LOW-10 mutacje, które przeżyły | poprawione testami; mutacje sprawdzone po poprawce (czerwone testy): `disabled = !allowed` (AdminApiTest), DELETE sesji bez sprawdzenia `sub` (GatewayIntegrationTest; kod był poprawny, brakowało testu), klucz sesji bez celu (VirtualServerMcpTest). Filtr portu na `getRequestURI()`: `InternalPortFilterTest` (jednostkowy, status z filtra). Certyfikat CA jako liść: `ClientCertificateVerifierTest` (CA z EKU clientAuth i CN `mcp-portal-bff`) |

Z przeglądu M1: LOW-8 (Prometheus bez uwierzytelnienia) zamknięte tą samą zmianą.

## Co zostało

M3 (odroczone z M2, decyzja koordynatora 2026-10-28): Cedar `call` z paczką i `prv`; rejestr manifestów z `definitionHash` i zatwierdzaniem; `activity`; `policy/status`;
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
