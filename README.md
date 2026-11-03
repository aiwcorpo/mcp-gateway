# mcp-gateway

MCP Gateway platformy MCP (strumień ws-05): jedyny punkt wejścia klientów AI. Uwierzytelnia użytkownika
tokenem z IdP (C1), pobiera z brokera poświadczenie użytkownika do systemu (C4), wystawia wewnętrzny JWT (C2)
i przekazuje wywołanie do serwera MCP po mTLS z nagłówkami C3. Każde wywołanie narzędzia zostawia zdarzenia
audytu C8 z jednym `requestId`.

Dla kogo: produkt dla operatorów platformy (komponent wdrażany jako obraz kontenera `mcp-gateway`, nie biblioteka). Instalacja i codzienna obsługa
całej platformy: repozytorium `mcp-docs` (w przygotowaniu); tutaj sekcja "Instalacja i obsługa" dla samego gatewaya. Licencja: Apache-2.0
([LICENSE](LICENSE), [NOTICE](NOTICE)); zgłaszanie podatności: [SECURITY.md](SECURITY.md); zmiany: [CHANGELOG.md](CHANGELOG.md); udział w pracach: [CONTRIBUTING.md](CONTRIBUTING.md).

Stan: kamień M6, etap 3 (wyłącznik awaryjny, kanał adaptera i klasyfikacja narzędzi obcych serwerów, `list_changed` w obu postaciach protokołu;
sekcja "Co dochodzi w M6") na M5 (jeden adres `/mcp` z filtrem w query zamiast zapisanych linków, HA dwóch instancji, CI w `ci/run.sh`; sekcja "Co dochodzi w M5") na M4 (przypinanie definicji w rejestrze, offboarding, limity zapytań, typ poświadczenia w Cedar, tryb dev tylko ze
stosem dev) na M3 (potwierdzenia TOTP akcji DESTRUCTIVE, Cedar z podpisanych paczek, `/activity/calls`), M2 (wirtualne serwery,
API C5 dla BFF, jedna domena) i M1 (OAuth RS, broker, C2/C3, audyt). Co działa, czego nie ma i odstępstwa: [STATUS.md](STATUS.md).
Kontrakty: `mcp-contracts` 6.3.2.

## Instalacja i obsługa

Gateway to jeden obraz kontenera (`mcp-gateway:<wersja>`, JRE 25 na glibc, użytkownik bez uprawnień, porty `8080` i `8443`). Potrzebuje działających:
PostgreSQL (rejestr, wyłączniki, aktywność; schemat zakłada Flyway przy starcie), Redis z kontem `gateway` (sesje, potwierdzenia, limity;
polityka `noeviction`, `appendonly yes`), IdP z OIDC (Keycloak lub Entra), brokera `mcp-credential-broker`, serwera polityk z podpisanymi paczkami
(`mcp-policies`) i serwerów MCP po mTLS z jednego wewnętrznego CA. Stos do próby na jednej maszynie: `mcp-platform-dev` (nie do produkcji).

**Wymagane zmienne** (reszta ma wartości domyślne, patrz `application.yml`):

| Zmienna | Znaczenie |
| --- | --- |
| `MCP_PUBLIC_URL` | publiczny origin (RFC 9728, `connectUrl`); nigdy z nagłówka `Host` |
| `MCP_OIDC_ISSUER`, `MCP_OIDC_JWKS_URI` | wystawca i klucze IdP; `MCP_OIDC_CLIENT_ID/SECRET/TOKEN_URI` tylko dla systemów `token-exchange` |
| `MCP_DB_URL`, `MCP_DB_USER`, `MCP_DB_PASSWORD` | PostgreSQL |
| `MCP_REDIS_HOST`, `MCP_REDIS_USER`, `MCP_REDIS_PASSWORD` | Redis (`MCP_REDIS_WAIT_REPLICAS` > 0 przy replikach) |
| `MCP_TLS_KEYSTORE`, `MCP_TLS_TRUSTSTORE`, `MCP_TLS_STORE_PASSWORD` | certyfikat gatewaya (CN `mcp-gateway`) i wewnętrzne CA |
| `MCP_BROKER_URL`, `MCP_BROKER_TLS_NAME` | broker |
| `MCP_POLICY_MAIN_URL`, `MCP_POLICY_MAIN_KEY_ID`, `MCP_POLICY_MAIN_KEY_FILE`, `MCP_POLICY_STATE_DIR` | paczki polityk; katalog stanu osobny dla instancji (wolumen) |
| `MCP_INTERNAL_JWT_KEYS_FILE`, `MCP_INTERNAL_JWT_ACTIVE_KID` | klucze C2, wspólne dla instancji |
| `MCP_LIST_CURSOR_KEY`, `MCP_ACTIVITY_CURSOR_KEY` | klucze HMAC kursorów, wspólne dla instancji |
| `MCP_SERVER_<SYSTEM>_MCP_URL`, `MCP_SERVER_<SYSTEM>_ADAPTER` | adres serwera systemu; `true` dla obcego serwera za adapterem |

**Codzienna obsługa.**

- *Gotowość:* `GET https://<gateway>:8443/actuator/health` z certyfikatem z wewnętrznego CA. Instancja, która nie czyta wyłączników awaryjnych, nie jest gotowa.
- *Dwie instancje i więcej:* wspólny Redis i PostgreSQL, ten sam plik kluczy C2 i te same klucze kursorów, osobny `MCP_POLICY_STATE_DIR` na instancję. Balancer:
  `proxy_next_upstream error timeout` bez `non_idempotent`, `proxy_buffering off` i `proxy_read_timeout` co najmniej 60 s dla `/mcp` i `/s/` (strumienie).
  Zmiany rejestru i wyłączników dochodzą do pozostałych instancji w ciągu sekundy (`MCP_CHANGE_POLL_INTERVAL`), skutek wyłącznika najpóźniej po 5 s.
- *Aktualizacja:* nowy obraz z tym samym `MCP_*`, migracje Flyway idą przy starcie; kolejno po jednej instancji. Strumienie SSE kończą się przy zatrzymaniu
  instancji (klient otwiera nowy).
- *Przejście z M5 (obraz `m6-01c9f5a` i starsze) na M6 i cofnięcie.* Migracje V8 i V9 są addytywne i działają przy dwóch instancjach (blokada Flyway), a stara wersja
  uruchomi się na bazie po V9 (ignoruje nowe migracje), ale **nie zna wyłączników awaryjnych**: stara instancja ich nie sprawdza, a `PUT`/`DELETE .../kill-switch` skierowane do niej dają `404`.
  Dlatego: (1) przy aktualizacji kroczącej nie wyłączaj niczego wyłącznikiem, dopóki wszystkie instancje nie są na M6 (w oknie wyłącznik działa tylko na nowych); (2) przed cofnięciem
  do M5 zdejmij ruch do serwerów z aktywnym wyłącznikiem (`MCP_SERVER_<SYSTEM>_ENABLED=false` w konfiguracji, albo nie cofaj), bo po cofnięciu wyłączniki przestają działać po cichu;
  (3) po aktualizacji do wersji z migracją V10 klasyfikacje `UPDATE`/`DESTRUCTIVE` adaptera tracą ważność (migracji nie da się cofnąć; wersja sprzed V10, od `476687d`, zna adapter, ale znowu przyjmie klasyfikację `UPDATE` albo `DESTRUCTIVE`, której V10 już nie unieważni, więc po cofnięciu zatwierdzaj narzędzia adaptera ostrożnie; wersja z V10 nie serwuje wpisu adaptera z ryzykiem innym niż `READ_ONLY`; krok V10 aktualizuj bez okna mieszanego instancji, bo stara instancja nie przeładuje rejestru, dopóki się nie zrestartuje albo nie zatwierdzi czegoś, co podbije licznik); (4) serwer za adapterem (`source: adapter`, wpisy bez `risk`) stara wersja wyłączy (manifest nie przechodzi jej walidacji, fail-closed); stara wersja nie wstanie też z serwerem
  adaptera bez wpisów `tools` w konfiguracji.
- *Wyłącznik awaryjny:* portal (administrator `mcp-platform-admin`) albo `PUT/DELETE /admin/v1/registry/servers/{serverId}[/tools/{tool}]/kill-switch`; lista `GET /admin/v1/kill-switches`;
  alert na zdarzenie `admin_change` z powodem `kill_switch_set` oraz na metrykę `mcp_gateway_kill_switches_unreadable` = 1.
- *Nowy obcy serwer:* `MCP_SERVER_<SYSTEM>_ADAPTER=true`, certyfikat adaptera `mcp-adapter-<serverId>`; adapter wysyła manifest przy starcie, administrator klasyfikuje
  i zatwierdza narzędzia w portalu. Do czasu zatwierdzenia narzędzia są niewidoczne.
- *Diagnostyka:* zdarzenia audytu C8 są na stdout (logger `AUDIT`), jedna linia JSON; po `requestId` z odpowiedzi składa się ślad wywołania z gatewaya, brokera i serwera.
  Metryki: sekcja "Metryki" poniżej. Najczęstsze objawy: `503` z `Retry-After` (przeciążenie albo magazyn sesji), `tool_disabled` z powodem `kill_switch` albo `definition_changed`
  w audycie, `upstream_unavailable` przy nieczytelnym stanie wyłączników.
- *Kopie zapasowe:* PostgreSQL (rejestr, wyłączniki, aktywność). Redis jest stanem krótkim; po jego utracie użytkownicy inicjują sesje ponownie.

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
    `sub` tokenu; obcy `sub` -> 404 jak sesja nieznana), `DELETE` kończy sesję, `GET` z `Accept: text/event-stream` otwiera strumień sesji (od M6), inny `GET` -> 405;
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

- **Wirtualne serwery (linki, C5):** zastąpione w M5 przez filtr w adresie (sekcja "Co dochodzi w M5"); `/v/<slug>/mcp` odpowiada 404, tabela i API linków nie istnieją.
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
  Metadane RFC 9728 leżą pod `/.well-known/oauth-protected-resource` i `.../mcp`, `.../s/<serverId>/mcp`
  (inne ścieżki pod tym prefiksem: 404). Na każdej odpowiedzi portu publicznego, błędy i błędy kontenera
  (nieprawidłowe żądanie HTTP) też, są `X-Content-Type-Options: nosniff` i `Content-Security-Policy: default-src
  'none'; sandbox`; nigdy `Set-Cookie`; `Cookie` klienta jest ukrywany przed aplikacją (do serwera i brokera i tak
  idą nagłówki budowane od zera); odpowiedzi to `application/json` także przy `Accept: text/html`. Reverse proxy
  (ws-01) dokłada te same nagłówki i usuwa `Cookie` na `/mcp`, `/s/` i `/.well-known/oauth-protected-resource*`.
- **Serwery:** konfiguracja wszystkich pięciu systemów (`application.yml`): adres, polityka poświadczeń, `enabled`,
  przełącznik `disabled` narzędzia i minimalne ryzyko. Narzędzia pochodzą od M3 z zatwierdzonego manifestu (niżej).

## Co dochodzi w M3

- **Potwierdzenia TOTP (C11).** Narzędzie `DESTRUCTIVE` przy pierwszym wywołaniu tworzy oczekujące wywołanie w Redis
  (klucz: `sub`, serwer, narzędzie, SHA-256 kanonicznych argumentów bez `confirmation_code`; TTL 120 s, 3 próby) i
  odpowiada `confirmation_required` z `confirmationId`, `description`, `previewUrl`, `expiresAt`. Ponowienie z tymi samymi
  argumentami i `confirmation_code` (6 cyfr z aplikacji Authenticator) sprawdza broker (`POST /v1/authenticator/verify`);
  kod nie trafia do serwera, logów ani audytu. Stan użytkownika to jedna wartość w Redis zmieniana skryptem
  compare-and-set (`RedisConfirmationStore`), więc utworzenie oczekującego i unieważnienie poprzedniego, rezerwacja próby i
  zużycie przy `ok` są atomowe; reguły są w `ConfirmationRules` (funkcje czyste, wektory `confirmation-binding/`).
  Jedna oczekująca DESTRUCTIVE na użytkownika, po otwarciu podglądu pierwsza wygrywa (`confirmation_blocked`), tworzenie
  nowej po obejrzanej woła `invalidate-codes`, `cancel` też. Utrata stanu to brak potwierdzenia; po utracie znacznika epoki
  (`gw:conf:epoch`) przez 210 s pierwsze tworzenie na `sub` pali kody. C5: `GET /confirmations/{id}`, `POST .../viewed`,
  `POST .../cancel`.
- **Polityka.** `ToolAuthorizer` to ocena Cedar `call` (`CedarToolAuthorizer`) z paczek podpisanych Ed25519, pobieranych
  przez `PolicyService` (`latest.json` z ETag, bez przekierowań, do 16 MiB; główna co 30 s, `overrides` co 5 s) i ładowanych
  przez `PolicyStore` (podpis, schemat, rewizja rosnąca, stan na dysku `MCP_POLICY_STATE_DIR`). Bez paczki głównej gateway
  nie startuje; po restarcie z aktywnymi `overrides` czeka na nie `MCP_POLICY_*` do końca okresu karencji. Do Cedar idą
  grupy z tokenu, zasoby z `resourceRefs` (kontekst `refs`); `prv` w JWT to rewizja
  paczki głównej.
- **Rejestr.** Tryb `required` (domyślny, `MCP_REGISTRY_MODE`): serwer ma tylko narzędzia z zatwierdzonego manifestu C6; zasady
  zatwierdzania, przypinania definicji i certyfikatu potoku: sekcja "Co dochodzi w M4". Obniżone ryzyko, także po usunięciu i
  dodaniu narzędzia, jest odrzucane, a narzędzie zatwierdzone poniżej minimum z konfiguracji lub najwyższego wcześniej
  zatwierdzonego ryzyka nie jest serwowane (także po restarcie). Instancje przeładowują stan z tabel co kilka sekund.
- **Aktywność.** `GET /admin/v1/activity/calls`: jeden wiersz na wywołanie (zdarzenia z PostgreSQL, agregacja według
  wektorów `activity-calls/`), kursor `X-Next-Cursor` z HMAC związanym z `sub`; `GET /admin/v1/activity` to ostatnie zdarzenia.
- **Uwierzytelnianie.** Niedostępny JWKS IdP (także nieznany `kid`) to 503 `upstream_unavailable` z `Retry-After`; odrzucone
  certyfikaty klienta i tokeny BFF na porcie C5 to zdarzenia `authentication`, próbkowane po jednym na adres na minutę;
  `missing_token` i `malformed` mają osobne budżety 20 zdarzeń na sekundę, nadmiar zlicza
  `mcp_audit_authentication_suppressed_total{component,reason}`.

**Wymagania wdrożeniowe stanu potwierdzeń.** Znacznik epoki (`gw:conf:epoch`) wykrywa tylko całkowitą utratę danych Redis. Nie
wykrywa: eksmisji kluczy z TTL (polityki `volatile-*`), failoveru z replikacją asynchroniczną (gateway nie robi `WAIT`) ani
przywrócenia Redis z kopii. Przy każdej z tych sytuacji ślad obejrzanej operacji może zniknąć bez zmiany epoki, a kod wpisany
dla A potwierdziłby wtedy B. Dlatego: `maxmemory-policy noeviction`, `appendonly yes` (utrata do 1 s zapisów przy `everysec`),
żadnego przywracania z kopii (zamiast tego usunięcie kluczy `gw:conf:*`, co uruchamia okno spalania kodów) i żadnego
failoveru bez synchronicznej replikacji, dopóki HA (M4) nie doda `WAIT`. ACL gateway'a nie ma `CONFIG`, więc ustawień nie
sprawdza. Stan użytkownika ma limit 20 śladów zastąpionych operacji.

**Obraz.** Biblioteka natywna Cedar jest rozpakowywana do `java.io.tmpdir`: kontener z `read_only: true` potrzebuje zapisywalnego
`/tmp`. Obraz nie ma `curl` ani `wget` (healthcheck przez `bash` i `/dev/tcp`). Sprawdzony na arm64 (glibc); x86_64 nie.

**Proces na hoście** (`scripts/run-dev-host.sh`) używa własnego schematu `host_gateway` w bazie stosu (`MCP_DB_SCHEMA`), żeby nie
pisać do tabel gateway'a z compose.

**Tokeny klientów tylko dla C5.** Na `/mcp` i `/s/` token z `azp` z listy `gateway.oidc.c5-only-clients` (domyślnie
`mcp-portal-bff`) jest odrzucany 401 `invalid_claims` niezależnie od `aud`: dopuszczenie portalu w polityce dla katalogu i
linków nie otwiera wywołań narzędzi jego tokenem.

Przebieg na żywo: `scripts/m3-demo.sh` (po uruchomieniu skryptów z sekcji niżej; atrapa brokera z
`MCP_TEST_BROKER_TOTP=<sub>=<ziarno>`, kody z `mcpdev.py otp alice`).

## Co dochodzi w M4

- **Rejestr i przypinanie definicji (CC-097, CC-133, CC-161, CC-162).** `PUT /admin/v1/registry/servers/{serverId}` przyjmuje tylko
  certyfikat `mcp-registry-ci-<serverId>` równy `serverId` ze ścieżki (cały CN, wielkość liter; inny CN, także dawny `mcp-registry-ci`,
  to 403 i zdarzenie `client_certificate_rejected`). Ciało to manifest z przeglądanego commitu: nowe i zmienione narzędzia
  `READ_ONLY` są zatwierdzane (`definition_registered`), `UPDATE` i `DESTRUCTIVE` czekają (`pending_approval`, `source: ci`,
  `definition_submitted`), usunięte znikają (`tool_removed`). `approve` (`mcp-platform-admin`, hash równy `pendingHash`) daje 204,
  409 `hash_mismatch` albo 422 `risk_lowered`. Podłoga ryzyka to najwyższe ryzyko, jakie kiedykolwiek zgłoszono dla narzędzia,
  także we wpisie oczekującym (CC-167). `PUT` z niższym ryzykiem nie odrzuca manifestu: to jedno narzędzie jest `pending_approval`
  z `riskLowered: true` (`change` `new` dla narzędzia dodanego ponownie, także gdy wraca do starszej zatwierdzonej definicji), a
  reszta manifestu przechodzi; zatwierdzone wcześniej wpisy zostają w mocy. Jedyna droga w dół to `approve` z
  `acceptRiskLowering: true` (administrator; BFF żąda świeżego MFA i wysyła pole tylko przy `true`): podłoga spada do zatwierdzonego
  ryzyka, w audycie jest jedno zdarzenie `risk_lowered_by_admin` z polem `risk` zamiast `definition_approved`; bez flagi 422
  `risk_lowered`, flaga przy wpisie, który niczego nie obniża, jest ignorowana. Ryzyko z konfiguracji (`gateway.servers.*.tools.*.risk`)
  nie obniża się nigdy: `PUT` poniżej niego to 422 `risk_lowered`. Krok rejestracji w CI powinien pokazać `riskLowered: true` z
  odpowiedzi `200`, bo narzędzie znika z `tools/list` do decyzji. Rejestr, lista i diff są tylko dla administratorów (403 dla reszty).
  Stan leży w tabelach `registry_servers` (ostatni przyjęty manifest), `registry_tools` (zatwierdzony i oczekujący wpis narzędzia;
  Flyway V5 przenosi manifesty z M3 jako zatwierdzone) i `registry_risk_floor`.
- **Co widzi klient.** `tools/list` składa się z zatwierdzonych definicji, nie z odpowiedzi serwera; odpowiedź serwera tylko rozstrzyga,
  czy narzędzie wolno pokazać. Odczyt `tools/list` serwera jest ważny do TTL (domyślnie 30 s, najwyżej 60 s) i jest wspólny dla
  użytkowników; porównanie z zatwierdzonym hashem dzieje się przy każdym `tools/list` i przed każdym `tools/call`. Inna definicja
  (`definition_changed`) albo brak narzędzia na serwerze (`tool_not_served`) ukrywa je, a wywołanie to `tool_disabled`. Inna definicja
  z serwera zostawia wpis `source: server` (nie zastępuje wpisu `ci`; znika, gdy serwer wraca do zatwierdzonej). Odczyt, który się nie
  udał, niczego nie dowodzi: lista bierze ostatni odczyt, wywołanie dostaje `upstream_unavailable` i nie dociera do serwera.
- **Start.** Zapisany manifest, który nie przechodzi sprawdzeń (`credential_type_mismatch`, `environment_mismatch`), wyłącza serwer
  (`enabled: false`, narzędzia `tool_disabled`) bez kasowania; po rejestracji przechodzącego manifestu serwer wraca. Bootstrap manifestu
  z serwera istnieje tylko w trybie dev i zatwierdza wszystko (zaufanie przy pierwszym kontakcie).
- **Typ poświadczenia.** `gateway.servers.<id>.credential.type` (jeden z `accepted-types`; wystarcza, gdy typ jest jeden albo
  `token-exchange: true`; przy kilku wymagany) to typ domyślny systemu i trafia do `context.credentialType` każdej decyzji Cedar, przed oceną. To typ z
  konfiguracji systemu, nie typ poświadczenia użytego w wywołaniu: dla Jiry i GitLaba (użytkownik ma PAT albo OAuth) reguła Cedar
  nie może więc rozróżniać `user-oauth` od `user-secret`; sensowne są reguły o `service-account` i `token-exchange`. Rejestracja
  sprawdza, że manifest przyjmuje ten typ. `403 exchange_denied` z brokera to C10 `access_denied` bez grup, `422 system_not_configured`
  to `internal_error` z przyczyną w logu; oba zostawiają zdarzenie `credential_resolve`. `accepted-types` to zbiór typów systemu
  (CC-166): typ zwrócony przez brokera spoza zbioru to `internal_error` i `credential_resolve`/`credential_type_mismatch` (z typem
  brokera), poświadczenie nie jest użyte ani zapamiętane; zbiór nie miesza `service-account` z typami użytkownika (start odmawia,
  CC-168). Rejestracja wymaga, by manifest przyjmował każdy typ ze zbioru systemu (domyślna konfiguracja Jiry ma więc tylko
  `user-secret`, jak manifest serwera). `exchange_denied` to `tool_call` z `decision: allow` i `outcome: denied` (CC-165). Token wymieniony (`token-exchange`) bez
  `expiresAt` jest odrzucany.
- **Offboarding.** `POST /admin/v1/users/{sub}/purge` (certyfikat `mcp-offboarding`, bez tokenu) usuwa oczekujące potwierdzenia
  i ślady, sesje MCP w Redisie (indeks `gw:session:of:<sha256(sub)>`, bo konto Redis gateway'a nie ma `SCAN`) i cache poświadczeń
  instancji; zwraca 204 także dla nieznanego `sub`; zdarzenie `admin_change`/`user_purged` jest zawsze jedno, plus
  Aktywność zostaje do końca retencji. Awaria bazy albo Redisu to 503 (powtórz wywołanie).
- **Limity.** Liczniki w Redisie (okno od pierwszego żądania): użytkownik, (użytkownik, klient), (użytkownik, narzędzie), niższy limit
  dla DESTRUCTIVE i limity poszczególnych narzędzi. Żądanie odrzucone nie zużywa pozostałych liczników. `tools/call` ponad limit to C10
  `rate_limited` z `retryAfterSeconds` >= 1, inne żądania to 429 z `Retry-After`, bez `WWW-Authenticate` i bez `X-RateLimit-*`.
  Audyt `rate_limited_user|client|tool`, najwyżej jedno zdarzenie na użytkownika i powód w odstępie (domyślnie 10 s), reszta w
  `mcp_audit_rate_limited_suppressed_total{reason}`. Redis, który nie odpowiada, odrzuca żądanie (fail-closed,
  CC-167): `tools/call` dostaje C10 `upstream_unavailable`, inne żądania 503 `upstream_unavailable` z `Retry-After: 10` i ciałem z
  wektora `rate-limit-store-unavailable`; zdarzenie `tool_call` z powodem `upstream_unavailable`;
  WARN i licznik `mcp.gateway.rate.unavailable`. Start odmawia konfiguracji, w której limit DESTRUCTIVE jest wyższy niż zwykły limit
  narzędzia, okna spoza 1 s .. 1 h i limitu narzędzia mniejszego niż 1.
- **Tryb dev.** Klucze `dev-` (JWT C2 i paczki polityk) wymagają profilu `devstack` razem z `allow-test-keys`; `environment: dev`
  w manifeście jest odrzucany poza profilem `devstack` (422 `environment_mismatch`). Profil `devstack` i dwie zgody: sekcja niżej.
- **Paczki polityk.** Gateway ładuje paczki na schemacie 4.0.0 (`schemaVersion` w `manifest.json`; paczka 3.1.x to `schema_mismatch`).
  Ta sama rewizja co załadowana (`latest.json` wrócił) nie jest błędem: ETag jest zapamiętywany, paczka nie jest pobierana w kółko
  i nic nie trafia do logu na ERROR.

### Przejście z M3 na M4 (dla ws-01)

Sesje MCP klientów założone przez gateway M3 nie mają wpisu w indeksie sesji użytkownika, który czyta `purge`. Przy przełączeniu
na M4 unieważniamy je wszystkie: przed startem obrazu M4 usuń klucze `gw:session:*` w Redisie kontem `admin`
(`redis-cli --scan --pattern 'gw:session:*' | xargs -r redis-cli DEL`); klienci robią wtedy `initialize` od nowa (404 sesji to ich
sygnał). Pozostały stan Redisa (`gw:conf:*`, `gw:rl:*`) zostaje. Migracja Flyway V5 przenosi manifesty z M3 do `registry_tools`
jako zatwierdzone.

## Co dochodzi w M5

Kontrakty 5.1.0 (CC-169 ... CC-188). Wejście do platformy to jeden adres `<publicBaseUrl>/mcp` i, jak dotąd, `/s/<serverId>/mcp`.

- **`/mcp`:** `tools/list` to wszystkie narzędzia, które użytkownik może teraz wywołać: zatwierdzone, włączone, obsługiwane przez serwer z zatwierdzoną
  definicją, z decyzją Cedar na poziomie narzędzia (`mayCall`). Kolejność: system według `ServerId`, potem nazwa narzędzia, bajtowo. System bez połączenia
  konta zachowuje narzędzia (wywołanie daje `credential_required`); serwer, którego odczyt nie udał się w `MCP_TOOLS_LIST_TIMEOUT` (równolegle, 3 s),
  jest pominięty na tej liście i nic więcej się o nim nie wnioskuje. Strona ma 100 narzędzi, dalej `nextCursor` (HMAC związany z `sub` i filtrem, 15 minut,
  zły kursor to zawsze `-32602` i powód `invalid_cursor`). `initialize` zwraca `listChanged: false`, `GET` to `405` z `Allow: POST, DELETE`.
- **Filtr w query:** `systems`, `tools`, `access=read|write`, `exclude`, parsowany z surowego `getQueryString()` klasą `EndpointFilter` z `mcp-manifest`
  (nie z mapy parametrów kontenera: `%zz`, `?=x`, `?%ff=1` to `400 invalid_filter`, nigdy brak filtra). `400` po sprawdzeniu tokenu, zdarzenie
  `policy_decision` z powodem `invalid_filter` bez pola `filter`. Zdarzenia `tool_call`, `policy_decision`, `confirmation`, `credential_resolve` mają `filter`. Odmowy, które klient może powtarzać (`invalid_filter`, `filter_mismatch`, `invalid_cursor`, `tools/call` z `not_found_or_denied` dla `not_granted` i `filter_scope`) są zapisywane najwyżej raz na użytkownika, powód i cel w odstępie `MCP_RATE_LIMIT_AUDIT_INTERVAL` (10 s): celem jest nazwa narzędzia albo skrót query, filtra lub kursora (sam skrót, nigdy do zdarzenia), więc wywołanie innego narzędzia nie jest wyciszone przez wabik. Dla użytkownika i powodu żyje najwyżej `MCP_AUDIT_THROTTLE_MAX_TARGETS_PER_USER` (50) kluczy, nadmiar dzieli jeden klucz zbiorczy; limit liczy się osobno dla każdego powodu, więc tanie `invalid_filter` nie zużywa budżetu odmów narzędzi. Okno użytkownika i powodu zamyka timer (także bez dalszego ruchu) i przy kontrolowanym zamknięciu gateway zapisuje jedno zdarzenie podsumowujące z `suppressedCount`; liczbę różnych pominiętych celów (do 1000) widać w `mcp_audit_endpoint_summary_targets`, pominięcia w `mcp_audit_endpoint_suppressed_total{reason}`. Odrzucenie żądania działa zawsze. **Stan jest w pamięci instancji:** przy dwóch instancjach okna i klucze są osobne, więc klient, który przełącza się między nimi, dostaje do jednego zdarzenia na instancję i odstęp, a podsumowania wychodzą z każdej instancji osobno. Kontrola `invalid_filter` ponad limit transportu (zapytanie około 15 KB i więcej) to `400` albo `414` z `{"error":"invalid_request"}` z warstwy kontenera, bez `reason`.
- **Kolejność `tools/call` (CC-178):** nazwa znana i `mayCall` (inaczej `not_found_or_denied`, powód `not_granted`, także dla zakazu Cedar na narzędziu),
  (decyzja polityki, która nie mogła zapaść, `policy_unavailable` albo `policy_error`, to `upstream_unavailable` albo `internal_error` z prawdziwym powodem w audycie, nie `not_found_or_denied`; limit narzędzia liczy się dopiero po `mayCall`, więc narzędzie bez prawa i nieistniejące odpowiadają tak samo), filtr i trasa (`not_found_or_denied`, `filter_scope`), potem `tool_disabled` (także narzędzie czekające na pierwsze zatwierdzenie), `upstream_unavailable`,
  `credential_required`, dopiero potem decyzja Cedar z argumentami, bramka potwierdzenia i serwer. Skutek: poświadczenie jest pobierane przed
  potwierdzeniem `DESTRUCTIVE` (nie jest używane i nie trafia do cache; wywołanie z kodem pobiera własne pod swoim `requestId`), a narzędzie bez uprawnienia nie ma już `access_denied` z `requiredEntitlements` (to zostaje dla odmowy z argumentami).
- **Sesje (CC-172, CC-184):** sesja w Redisie niesie trasę i znormalizowany filtr z `initialize`. Kolejność: token, składnia query (`400`), `sub` sesji (cudza lub nieznana
  to `404` bez audytu), trasa i filtr (`404`, `filter_mismatch`). Dotyczy też `DELETE` i żądań z `Mcp-Session-Id` razem z `_meta`. Sesje bez trasy (z 4.x) są nieznane (CC-188).
- **Linki usunięte:** tabela `virtual_servers` (Flyway `V7`), API C5, limit, `vs`/`vsc` w JWT, część "linki" w `purge`. `/v/...` to `404 not_found_or_denied` bez
  audytu i bez względu na token (filtr serwletowy przed łańcuchem bezpieczeństwa); metadane `/.well-known/oauth-protected-resource/v/...` też `404`.
- **OAuth (V2):** zasób to `<publicBaseUrl>/mcp` bez query, `resource_metadata` bez query, dokument ignoruje query.
- **Aktywność (CC-188):** powód `link_scope` ze starych zdarzeń czytany jest jako `denied_filter_scope`, tak samo wynik `denied_link_scope`; dane nie są przepisywane.

### HA: dwie instancje

Stan wspólny leży w Redisie i PostgreSQL: sesje klientów i ich wiązanie z trasą i filtrem, potwierdzenia TOTP (porównaj-i-zapisz), limity, rejestr narzędzi (druga
instancja adoptuje zmianę co kilka sekund). Poza tym instancje potrzebują tego samego:

| Co | Jak | Bez tego |
| --- | --- | --- |
| klucze C2 | jeden plik JWKS (`MCP_INTERNAL_JWT_KEYS_FILE`, `MCP_INTERNAL_JWT_ACTIVE_KID`) | serwery nie zweryfikują tokenu z drugiej instancji |
| klucz kursora `/activity/calls` i `tools/list` | `MCP_ACTIVITY_CURSOR_KEY`, `MCP_LIST_CURSOR_KEY` | kursor z jednej instancji jest odrzucany na drugiej |
| `/app/state` | wolumen na instancję (blokada pliku `.instance.lock`: drugi proces na tym samym katalogu nie wstaje) | ochrona przed cofnięciem paczki polityk byłaby wspólna i błędna |
| `WAIT` | `MCP_REDIS_WAIT_REPLICAS=1` (wymagane poza `devstack`; `+wait` w ACL Redisa gateway'a) przy Redisie z repliką | po awarii mastera spalony kod albo oczekująca operacja mogą zniknąć |

Zmiana stanu potwierdzeń i `WAIT` idą na osobnym połączeniu Redis (każda zmiana własne), bo `WAIT` blokuje połączenie, a wspólne połączenie obsługuje limity i sesje: replika, która przestaje odpowiadać, kończy się odmową potwierdzenia po `MCP_REDIS_WAIT_TIMEOUT`, nie zatrzymaniem gateway'a. Poza profilem `devstack` gateway nie wstaje z kluczami generowanymi na proces ani z `MCP_REDIS_WAIT_REPLICAS=0` (te zmienne są wymagane). `/admin/v1/policy/status` zgłasza rewizję instancji,
która odpowiedziała; BFF za load balancerem widzi jedną instancję naraz. Utrata Redisa: sesje, limity i potwierdzenia odmawiają (`503` albo `upstream_unavailable`; odmowa sklepu sesji niesie ten sam `requestId` w nagłówku i w zdarzeniu audytu), żadna
odpowiedź nie jest zgadywana. Cache poświadczeń i sesje do serwerów są w pamięci instancji (czyszczone zdarzeniem `credential.invalidated` i TTL <= 60 s).

**Gwarancje przy ponowieniu klienta.** Kod potwierdzenia `DESTRUCTIVE` jest zużywany raz na wszystkich instancjach, także przy równoległych ponowieniach i zabiciu instancji w trakcie (test `HighAvailabilityTest`). Wywołanie `UPDATE` ma semantykę co najmniej raz: gateway nie deduplikuje wywołań, więc klient (albo load balancer), który ponawia wywołanie po zerwanym połączeniu z zabitą instancją, może wykonać je u serwera dwa razy; serwer powinien być na to odporny (idempotencja po stronie systemu docelowego).

### Przeciążenie: limit współbieżności zamiast braku pamięci

Każde żądanie działa na wirtualnym wątku, więc nic poza kontenerem nie ogranicza liczby żądań w toku; stojący system docelowy, baza (pula 10 połączeń, 3 s) albo wolny Redis piętrzą żądania, a każde trzyma bufory na stercie. Pomiar lokalny (`SaturationTest`, jedna instancja, 600 do 1200 wywołań naraz, system docelowy 400 ms): bez limitu serwer za gatewayem widział 258 wywołań naraz, `ActivityRecorder` zgłosił 689 razy `CannotGetJdbcConnectionException`, a żywy zbiór sterty po pełnym GC wynosił około 170 MB (z 1 GiB sterty; ze stertą 192 MB proces umarł z `OutOfMemoryError` w kilka sekund); z limitem 40 serwer widział najwyżej 40 wywołań, żywy zbiór około 50 MB, reszta dostała `503`. Pamięć rośnie więc liniowo z liczbą żądań w toku (bufory Tomcata i JSON-ów), a nie widać wycieku: próbki żywego zbioru w trakcie przebiegu są płaskie. Przyczyną braku pamięci w stosie jest brak ograniczenia żądań w toku razem z brakiem limitu pamięci kontenera (sterta JVM to 75% pamięci VM Dockera, współdzielonej z resztą stosu).

- `MCP_MAX_CONCURRENT_REQUESTS` (domyślnie 128): najwięcej żądań `POST` i `DELETE` na `/mcp` i `/s/<serverId>/mcp` obsługiwanych naraz. Żądanie, które nie dostanie miejsca w `MCP_CONCURRENCY_QUEUE_WAIT` (100 ms), dostaje `503` z `Retry-After` (`MCP_SHED_RETRY_AFTER_SECONDS`, 2 s) i `{"error":"upstream_unavailable"}` (kod C10), bez wywołania czegokolwiek za bramą. Filtr stoi za uwierzytelnieniem: żądanie bez ważnego tokenu dostaje `401` także przy pełnym gatewayu i nie zajmuje miejsca. Metryki: `mcp_gateway_requests_shed_total`, `mcp_gateway_requests_in_flight`; w logu najwyżej jedna linia na sekundę.
- Kolejka poleceń do wspólnego połączenia Redis ma limit (`max(1024, 16 x limit współbieżności)`); pełna kolejka kończy polecenie błędem, a wywołujący odmawia (fail-closed).
- Limit pamięci kontenera trzeba ustawić we wdrożeniu (`mem_limit` w compose, `resources.limits.memory` w Kubernetes): obraz ma `-XX:+UseG1GC`, `-XX:MaxRAMPercentage=60` i `-XX:G1PeriodicGCInterval=60000` (G1 jawnie: bez tego JVM wybiera Serial przy jednym CPU albo limicie poniżej ok. 1792 MB, a okresowe oddawanie pamięci działa tylko w G1), więc sterta liczy się od limitu kontenera (przy 2 GiB to 1,2 GiB; poza stertą proces zajmuje około 250 MB); bez limitu od pamięci całej maszyny. Opcje z wiersza poleceń obrazu wygrywają z `JAVA_TOOL_OPTIONS`, więc procent z compose nie działa. Pamięć kontenera widoczna w `docker stats` po szczycie ruchu to sterta, którą G1 zatrzymał, nie żywy zbiór; G1 oddaje ją okresowo (co 60 s). Cache poświadczeń usuwa wygasłe wpisy timerem co 10 s i ma limit 10 000 wpisów (metryki `mcp.gateway.credential.cache.size` i `.refused`). Wartość domyślna limitu współbieżności jest dobrana do puli bazy i Redisa, nie do pamięci; przy zmianie zmieniaj oba.

### Przejście z M4 na M5 (dla ws-01)

Obraz `mcp-gateway:m5-<sha>`; wymagane nowe zmienne poza dev: `MCP_LIST_CURSOR_KEY` i `MCP_REDIS_WAIT_REPLICAS` >= 1 (oraz dotychczasowe `MCP_ACTIVITY_CURSOR_KEY`, `MCP_INTERNAL_JWT_KEYS_FILE`). `MCP_TOOLS_LIST_TIMEOUT`
opcjonalnie. Sesje MCP sprzed aktualizacji są nieznane (klient inicjuje nową), stan potwierdzeń w Redisie zachowuje format (pole `virtualServer` rekordu jest ignorowane przy odczycie),
migracja usuwa tabelę linków. ACL Redisa: dodać `+wait`. Wejść razem ze starterem i serwerami na kontraktach 5.x (serwery odrzucają token z `vs`).

## Profil `devstack`: jedyne miejsce na relaksacje dev

Gateway nie wstaje (odmowa w `ApplicationContextInitializer`, przed pierwszym beanem, więc przed pobraniem paczek, kluczy IdP i manifestów; drugi raz sprawdza ją bean `devstackGuard`, od którego zależą beany używające relaksacji), jeśli konfiguracja używa któregokolwiek z poniższych, a
aktywny profil nie jest wyłącznie `devstack` z dwiema zgodami: właściwością `aiwcorpo.mcp.platform.devstack.acknowledged=true`
**i** zmienną środowiskową procesu `MCP_DEVSTACK_ACKNOWLEDGED=true` (wzorzec startera serwerów; obie mają być w konfiguracji stosu, nie w obrazie; zmienna liczy się tylko jako zmienna procesu, nie jako właściwość z argumentu, pliku czy `SPRING_APPLICATION_JSON`).
Same zgody bez profilu nic nie znaczą, profil bez obu zgód też nie. Zgody leżą w konfiguracji wdrożenia, więc skopiowanie całego bloku `environment:` stosu dev razem z profilem i obiema zgodami przejdzie strażnika: chroni to przed pojedynczym ustawieniem, które wpadnie samo, nie przed skopiowaniem całości (widać ją po WARN i gauge).

| Relaksacja | Ustawienie |
| --- | --- |
| klucze podpisu `test-*` JWT C2 | `MCP_INTERNAL_JWT_ALLOW_TEST_KEYS=true` |
| klucze `test-*` paczek polityk | `MCP_POLICY_ALLOW_TEST_KEYS=true` (bez niego biblioteka paczek odrzuca klucze `test-*`) |
| bootstrap manifestów z serwera | `MCP_REGISTRY_BOOTSTRAP=true` |
| narzędzia z `application.yml` zamiast zatwierdzonego manifestu | `MCP_REGISTRY_MODE=static` albo `manifest: static` serwera |
| http | `MCP_ALLOW_PLAIN_HTTP=true`; `MCP_PUBLIC_URL`, `MCP_OIDC_JWKS_URI`, `MCP_OIDC_TOKEN_URI`, `MCP_POLICY_MAIN_URL`, `MCP_POLICY_OVERRIDES_URL` bez `https` |
| brak ochrony przed cofnięciem paczek | puste `MCP_POLICY_STATE_DIR` |

Każdy start z profilem loguje `WARN event=devstack_profile` z listą użytych relaksacji, a gauge `mcp_gateway_devstack_active`
ma wartość 1 (manifest ani audyt nie mają pola na środowisko). Bez profilu odrzucone są także klucze `test-*` (JWT i paczki),
bootstrap jest wyłączony, a adresy IdP i paczek muszą być `https`.

Dla stosu `mcp-platform-dev` (compose, usługa `mcp-gateway`) ws-01 ustawia: `SPRING_PROFILES_ACTIVE=devstack`,
`MCP_DEVSTACK_ACKNOWLEDGED=true`, `AIWCORPO_MCP_PLATFORM_DEVSTACK_ACKNOWLEDGED=true` oraz tylko te relaksacje z tabeli, których
stos naprawdę używa (dziś: `MCP_POLICY_ALLOW_TEST_KEYS=true`, `MCP_ALLOW_PLAIN_HTTP=true`, `MCP_REGISTRY_MODE=static`,
`MCP_REGISTRY_BOOTSTRAP=true`, adresy http IdP i serwera paczek). Czego stos nie używa, zostaje domyślne (odrzucone).

## Konfiguracja

Zmienne środowiska (nazwy z `mcp-platform-dev`, usługa `mcp-gateway` profilu `full`); pełna lista w
`gateway/src/main/resources/application.yml`.

| Zmienna | Znaczenie |
| --- | --- |
| `MCP_OIDC_ISSUER`, `MCP_OIDC_JWKS_URI`, `MCP_OIDC_AUDIENCE` | C1: oczekiwany `iss`, JWKS IdP, audience (domyślnie `mcp-gateway`) |
| `MCP_OIDC_AUTHORIZATION_SERVER` | serwer autoryzacji w RFC 9728; domyślnie `MCP_OIDC_ISSUER` |
| `MCP_OIDC_TOKEN_URI`, `MCP_OIDC_CLIENT_ID`, `MCP_OIDC_CLIENT_SECRET` | token exchange dla systemów `token-exchange` |
| `MCP_PUBLIC_URL` | wymagany: publiczny origin portalu i gateway'a (`https://...`, `http://` tylko z `MCP_ALLOW_PLAIN_HTTP`), bez ścieżki; źródło `resource_metadata` i `connectUrl` |
| `MCP_DB_URL`, `MCP_DB_USER`, `MCP_DB_PASSWORD` | PostgreSQL (baza `gateway`): rejestr narzędzi i aktywność; Flyway migruje przy starcie (`V7` usuwa tabelę linków), bez bazy gateway nie wstaje |
| `MCP_ADMIN_AUDIENCE`, `MCP_ADMIN_AUTHORIZED_PARTY` | C5: `aud` tokenu BFF (domyślnie `mcp-gateway-admin`, token z `aud` `mcp-gateway` jest odrzucany, a token MCP z `aud` admina też) i wymagane `azp` (domyślnie `mcp-portal-bff`) |
| `MCP_ADMIN_CLIENT_CNS`, `MCP_ADMIN_OFFBOARDING_CLIENT_CNS` | C5: CN certyfikatów klienta dla operacji BFF (domyślnie `mcp-portal-bff`) i dla `purge` (domyślnie `mcp-offboarding`); CN potoku rejestru nie jest konfiguracją: `mcp-registry-ci-<serverId>` równe `serverId` ze ścieżki (CC-161). Przydział operacji jest w kodzie wg `x-allowed-client-cn`, operacja spoza kontraktu to 403 dla każdego CN |
| `MCP_REGISTRY_DEFINITION_CHECK_TTL` | jak długo odczyt `tools/list` serwera jest ważny (domyślnie 30 s, najwyżej 60 s; większa wartość zatrzymuje start) |
| `MCP_RATE_LIMIT_ENABLED`, `_WINDOW`, `_PER_USER`, `_PER_CLIENT`, `_PER_TOOL`, `_DESTRUCTIVE_PER_TOOL`, `_AUDIT_INTERVAL` | limity zapytań w oknie (domyślnie 1 min: 600 na użytkownika, 300 na parę użytkownik-klient, 120 na parę użytkownik-narzędzie, 10 na narzędzie DESTRUCTIVE); limit pojedynczego narzędzia: `gateway.rate-limit.tools.<system>__<narzędzie>` w `application.yml` |
| `MCP_ACTIVITY_RETENTION` | jak długo tabela aktywności trzyma zdarzenia (domyślnie `30d`, CC-134) |
| `MCP_TOOLS_LIST_TIMEOUT` | milisekundy, które ma jeden serwer na odczyt swojego `tools/list` przy liście klienta (domyślnie `3000`, wartość niedodatnia zatrzymuje start; CC-180) |
| `MCP_AUDIT_THROTTLE_MAX_TARGETS_PER_USER` | ile kluczy (użytkownik, powód, cel) żyje naraz w audycie powtarzalnych odmów na użytkownika i powód (domyślnie 50, CC-191) |
| `MCP_MAX_CONCURRENT_REQUESTS`, `MCP_CONCURRENCY_QUEUE_WAIT`, `MCP_SHED_RETRY_AFTER_SECONDS` | limit żądań MCP w toku (domyślnie 128), czas oczekiwania na miejsce (100 ms) i `Retry-After` odmowy 503 (2 s); sekcja "Przeciążenie" |
| `MCP_LIST_CURSOR_KEY` | klucz HMAC kursora `tools/list` (min. 16 bajtów), ten sam na każdej instancji |
| `MCP_REDIS_WAIT_REPLICAS`, `MCP_REDIS_WAIT_TIMEOUT` | ile replik musi potwierdzić zmianę stanu potwierdzeń (Redis `WAIT`, ACL gateway'a musi mieć `+wait`) i jak długo czekać; `0` = bez czekania (jeden Redis) |
| `MCP_METRICS_CLIENT_CNS` | CN certyfikatów klienta dla `/actuator/prometheus` (puste = nikt) |
| `MCP_SERVER_<SYSTEM>_MCP_URL`, `_ENABLED`, `_VERSION` | adres (`https`), wyłącznik i wersja serwera dla JIRA, CONFLUENCE, GITLAB, SERVICEDESK, OPENSEARCH; adresy domyślne `https://mcp-<system>.internal:8443/mcp`, dla Jiry `MCP_SERVER_JIRA_URL` + `/mcp` |
| `MCP_INTERNAL_PORT` | port wewnętrzny TLS, domyślnie `8443` |
| `MCP_INTERNAL_JWT_ISSUER` | `iss` C2, domyślnie `https://mcp-gateway.internal` |
| `MCP_INTERNAL_JWT_KEYS_FILE`, `MCP_INTERNAL_JWT_ACTIVE_KID` | prywatny JWKS (P-256, każdy klucz z `kid`) i aktywny `kid`; wspólny dla wszystkich instancji; puste = klucze generowane na proces, tylko w profilu `devstack` |
| `MCP_TLS_KEYSTORE`, `MCP_TLS_TRUSTSTORE`, `MCP_TLS_STORE_PASSWORD` | PKCS12 gateway'a (CN `mcp-gateway`, serverAuth+clientAuth) i CA |
| `MCP_BROKER_URL`, `MCP_BROKER_TLS_NAME` | broker i nazwa w jego certyfikacie (CC-035) |
| `MCP_REDIS_HOST`, `MCP_REDIS_PORT`, `MCP_REDIS_USER`, `MCP_REDIS_PASSWORD`, `MCP_REDIS_KEY_PREFIX` | Redis (ACL `gateway`, `gw:*`, `credential.invalidated`) |
| `MCP_SERVER_JIRA_URL` albo `MCP_SERVER_JIRA_MCP_URL` | adres `mcp-jira`; do pierwszego dopisywane jest `/mcp` |
| `MCP_POLICY_MAIN_URL`, `MCP_POLICY_OVERRIDES_URL` | wymagany katalog paczki głównej (`.../policies/main/`) i opcjonalny `overrides`; w compose `http://policies.internal:8080/policies/...` |
| `MCP_POLICY_MAIN_KEY_ID`, `MCP_POLICY_MAIN_KEY_FILE`, `MCP_POLICY_OVERRIDES_KEY_ID`, `MCP_POLICY_OVERRIDES_KEY_FILE` | identyfikatory i pliki PEM kluczy publicznych Ed25519 obu kanałów |
| `MCP_POLICY_ALLOW_TEST_KEYS` | tylko dev: klucze `test-*` (CC-044) |
| `MCP_POLICY_STATE_DIR`, `MCP_POLICY_MINIMUM_MAIN_REVISION`, `MCP_POLICY_MINIMUM_OVERRIDES_REVISION` | ochrona przed cofnięciem po restarcie (CC-066): katalog stanu jednej instancji (w obrazie `/app/state`), wymagany poza dev (bez `MCP_POLICY_ALLOW_TEST_KEYS`), i rewizje minimalne |
| `MCP_POLICY_MAIN_INTERVAL`, `MCP_POLICY_OVERRIDES_INTERVAL`, `MCP_POLICY_STARTUP_TIMEOUT` | 30 s, 5 s, 2 min do rezygnacji ze startu bez paczki |
| `MCP_REGISTRY_MODE`, `MCP_REGISTRY_BOOTSTRAP` | `required` (domyślnie) albo `static`; pobranie pierwszego manifestu od serwera bez zatwierdzenia (domyślnie NIE; tylko dev, patrz wyżej). Przełącznik `manifest` per serwer w `application.yml` |
| `MCP_ACTIVITY_CURSOR_KEY` | klucz HMAC kursora `/activity/calls` (min. 16 bajtów); wspólny dla instancji; puste = losowy na proces, tylko w profilu `devstack` |
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

## Co dochodzi w M6 (etap 3, kontrakty 6.2.0)

- **`list_changed` (CC-192, CC-207).** `capabilities.tools.listChanged: true` w obu postaciach protokołu. Strumień sesji: `GET` na `/mcp` albo `/s/<serverId>/mcp` z `Mcp-Session-Id` i
  `Accept: text/event-stream`, kontrole w kolejności CC-184 (token, składnia query `400`, właściciel sesji `404`, trasa i filtr `404` ze zdarzeniem `filter_mismatch`); bez sesji albo bez
  tego `Accept` to `405` z `Allow: POST, DELETE, GET`. Postać bezstanowa: `POST subscriptions/listen` (filtr z tego żądania, bez sesji, bez `filter_mismatch`); pierwsza wiadomość to
  `notifications/subscriptions/acknowledged` z podzbiorem filtra klienta, który gateway spełnia (`toolsListChanged`), potem puste `notifications/tools/list_changed` z `subscriptionId`;
  przy końcu z inicjatywy serwera odpowiedź `resultType: complete` na żądanie. Punkt odniesienia to lista użytkownika z chwili otwarcia strumienia (`UserToolLists`: zatwierdzone,
  włączone, bez wyłącznika, ostatni odczyt serwera nie przeczy hashowi, Cedar na poziomie narzędzia); porównanie po filtrze adresu według nazwy, ryzyka i hasha definicji; najwyżej jedno
  powiadomienie na sekundę (`ListChangeTracker`, wektory `list-changed-*`). Wyzwalacze: zmiana rejestru (także na innej instancji, licznik `registry_changes` w PostgreSQL czytany co
  `MCP_CHANGE_POLL_INTERVAL`, domyślnie 1 s), wyłącznik, nowa paczka polityk, inny wynik odczytu definicji serwera, zmiana grup w tokenie sesji z otwartym strumieniem. Strumień nie liczy
  się do `MCP_MAX_CONCURRENT_REQUESTS` (żądanie oddaje miejsce, gdy okaże się strumieniem), nie ma limitu strumieni na użytkownika, otwarcie strumienia liczy się do zwykłych limitów żądań
  użytkownika i klienta (429), instancja trzyma najwyżej `MCP_MAX_OPEN_STREAMS` strumieni (domyślnie 2000, oba rodzaje razem; powyżej `503` jak przy przeciążeniu, z `Retry-After`,
  metryka `mcp_gateway_streams_refused_total`), a liczba otwartych to metryka; po zmianie listy liczy się najwyżej `MCP_STREAM_RECOMPUTE_PARALLELISM` list naraz (domyślnie 4), a seria zmian to jedno przeliczenie na strumień. Heartbeat
  `: keepalive` co `MCP_SSE_HEARTBEAT_INTERVAL` (15 s). Koniec strumienia: wygaśnięcie tokenu, `DELETE` sesji, `purge` użytkownika (na tej instancji; na innej strumień sesji kończy się przy następnym heartbeacie, najwyżej po 15 s, bo sesji już nie ma, a bezstanowy dopiero z wygaśnięciem tokenu, najwyżej po 60 min), zatrzymanie procesu. Zdarzenia nie są odtwarzane. Lista strumienia jest liczona raz na tożsamość (sub, nazwa, klient, grupy): decyzje Cedar są pamiętane do następnej paczki polityk i dotyczą narzędzi o tym samym odcisku (serwer, nazwa, ryzyko, akcja, typ poświadczenia, `resourceRefs`), więc wyłącznik, zmiana odczytu serwera i zmiana jednego narzędzia nie kosztują decyzji dla reszty, a strumienie jednej tożsamości dzielą wynik; strumienie liczą w osobnej, małej puli (nie dzielą slotów z `tools/list` klientów). Strumień sesji na `/s/<serverId>/mcp` porównuje tylko narzędzia tego systemu; `subscriptions/listen` bez `toolsListChanged` nie liczy list. Zmiana grup w tokenie sesji z otwartym strumieniem zmienia jego listę przy następnym żądaniu tej sesji. Granice: dostępność serwera i dryf jego definicji wyzwalają powiadomienie dopiero po odczycie
  przez ruch (`tools/list`, `tools/call`); zmiana grup strumienia bezstanowego dociera z nowym tokenem (nowy strumień).
- **Wyłącznik awaryjny (CC-194, A9).** Tabela `kill_switches` (Flyway V8), operacje C5 `putServerKillSwitch`, `deleteServerKillSwitch`, `putToolKillSwitch`, `deleteToolKillSwitch`,
  `listKillSwitches` (administrator `mcp-platform-admin`, `mcp-portal-bff`); włączenie bez MFA, bez wygasania. Sprawdzany w `tools/call` po `mayCall` i po filtrze adresu, przed
  `tool_disabled` z konfiguracji (powód audytu `kill_switch`, kod `tool_disabled`; użytkownik bez prawa do narzędzia albo z filtrem, który je wycina, dostaje `not_found_or_denied`).
  Pamięć podręczna instancji nie starsza niż `MCP_KILL_SWITCH_CACHE_TTL` (5 s) i nigdy nie wydłużana po nieudanym odczycie; nieczytelny stan to `upstream_unavailable` dla wywołania,
  pusta `tools/list`, `503` katalogu i brak gotowości. Katalog pokazuje `disabledBy` (`kill_switch`, `approval`, `configuration`). Oczekujące potwierdzenie narzędzia z wyłącznikiem
  kończy się przy ponowieniu z kodem odmową `tool_disabled`. `PUT` dla narzędzia nieznanego rejestrowi to `404`, `DELETE` przełącznika narzędzia usuniętego z manifestu to `204`.
- **Kanał adaptera i klasyfikacja (CC-193, CC-206, CC-207).** `gateway.servers.<id>.adapter: true` (`MCP_SERVER_<SYSTEM>_ADAPTER`) oznacza serwer za adapterem; jego manifest (`source: adapter`,
  wpisy bez `risk` i `action`) przychodzi na `PUT /admin/v1/registry/adapters/{serverId}` z certyfikatem `mcp-adapter-<serverId>`; kolejność odpowiedzi: certyfikat (`403`), `serverId` ciała
  względem ścieżki (`400`), tryb i `source` (`422 adapter_mode_mismatch`, także dla pipeline'u na serwerze adaptera), kontrole każdego manifestu (`422`). Wywołanie niczego nie zatwierdza:
  każde nowe lub zmienione narzędzie jest `pending_approval` ze `source: adapter`, narzędzie nieobecne w manifeście jest usuwane razem z klasyfikacją i podłogą ryzyka. `approve`
  przyjmuje `risk` i `action` (tylko `READ_ONLY` z `read`, CC-227: `UPDATE` i `DESTRUCTIVE` to `422 classification_not_allowed`; wymagane dla wpisu adaptera: `classification_required`, zabronione dla innych: `classification_not_allowed`, zgodne ze sobą: `classification_inconsistent`);
  obniżenie klasyfikacji wymaga `acceptRiskLowering`; klasyfikacje `UPDATE` i `DESTRUCTIVE` zapisane przez wcześniejszą wersję traci ważność migracja `V10` (wpis wraca do `pending_approval`, ukryty jako `tool_disabled`, klasyfikacja zostaje podłogą, więc ponowne zatwierdzenie jako `READ_ONLY` to obniżenie z `acceptRiskLowering` i świeżym MFA); wywołanie narzędzia serwera adaptera niesie w wewnętrznym JWT claimy `mcp_risk` i `mcp_action` (CC-226; tylko dla serwera w trybie adaptera, tylko zgodna para i tylko z `tool`; serwer natywny i broker odrzucają je jako `invalid_claims`); hash wpisu adaptera nie obejmuje `risk` ani `action`; zdarzenie `admin_change` niesie `risk` i `action`. Narzędzie bez klasyfikacji jest
  oceniane jak najbardziej niebezpieczne (DESTRUCTIVE, `admin`), więc tylko użytkownik z takim prawem w ogóle widzi je jako `tool_disabled`. Różnica znaleziona przy odczycie działającego
  serwera adaptera to wpis `source: adapter`, nigdy `server`.
- **Audyt i odpowiedzi.** Zakaz `forbid` na poziomie narzędzia to w audycie `policy_forbid` (klient: `not_found_or_denied`, wiersz aktywności: `denied_not_granted`); podsumowania
  ograniczania zdarzeń mają `suppressedTargets`; `503` przy przeciążeniu ma `Retry-After: 2` (`MCP_SHED_RETRY_AFTER_SECONDS`), `503` przy niedostępnym magazynie sesji `Retry-After: 10`
  (`MCP_SESSION_STORE_RETRY_AFTER_SECONDS`); `cursor: ""` w `tools/list` to `-32602`; claimy tokenu IdP spoza znanych (w tym `vs`, `vsc`) są ignorowane i nigdy nie trafiają do JWT C2;
  gateway nie ponawia sam `tools/call` o ryzyku `UPDATE` ani `DESTRUCTIVE` (po utracie sesji przez serwer klient dostaje `upstream_unavailable` i decyduje).
- **Skala strumieni (pomiar w STATUS.md).** 2000 strumieni 500 tożsamości, 253 narzędzia, 12 rdzeni: powiadomienie o wyłączniku do wszystkich w 0,3 s, o zmianie jednego narzędzia w 0,7 s,
  `tools/list` klienta w czasie burzy bez zmiany (ok. 140 ms). Zmiana paczki polityk nie ma gwarancji 5 s dla `list_changed` (CC-228): nowa paczka i otwarcie strumienia nowej tożsamości kosztują pełne przeliczenie (ok. 0,18 s na tożsamość, 5 tożsamości na sekundę),
  więc dla polityk nie ma obietnicy 5 s przy setkach tożsamości.
- **Koszt `tools/list`.** Decyzje Cedar o narzędziach jednego serwera liczą się równolegle (`ToolAccess`) i raz na narzędzie; 253 narzędzia: 883 ms po kolei, 162 ms równolegle
  na 12 rdzeniach, 493 ms na 2 rdzeniach (`ToolsListCostTest`). Jedna decyzja to ok. 3,4 ms, prawie w całości wywołanie natywnej biblioteki Cedar.

### Metryki M6

| Metryka | Znaczenie |
| --- | --- |
| `mcp_gateway_open_streams` | otwarte strumienie SSE na instancji (sesje i `subscriptions/listen` razem) |
| `mcp_gateway_streams_opened_total{kind}` | otwarte strumienie, `kind` = `session` albo `listen` |
| `mcp_gateway_streams_closed_total{reason}` | zamknięte strumienie (`token_expired`, `session_deleted`, `user_purged`, `shutdown`, `client_closed`, `interrupted`) |
| `mcp_gateway_streams_refused_total` | strumienie odrzucone przez `MCP_MAX_OPEN_STREAMS` |
| `mcp_gateway_stream_notifications_total` | wysłane `notifications/tools/list_changed` |
| `mcp_gateway_kill_switches_active` | wyłączniki, które instancja ostatnio odczytała |
| `mcp_gateway_kill_switches_unreadable` | 1, gdy instancja nie czyta wyłączników i odmawia wywołań |
| `mcp_gateway_requests_in_flight`, `mcp_gateway_requests_shed_total` | bez zmian: żądania w toku (bez strumieni) i odrzucone przez limit |

## Budowanie i testy

Wymaga JDK 25 i Dockera (Testcontainers: Redis z ACL jak w `mcp-platform-dev` i PostgreSQL 18.6).

```bash
# JDK 25 w PATH albo w JAVA_HOME; na Windows przez WSL2
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
| `AdminApiTest` | C5 przez mTLS: certyfikat BFF, innego komponentu, obcego CA, serwera (serverAuth) i brak; token dla złego `aud`; JWKS nadal pobierany przez klientów z dowolnym certyfikatem; katalog z polityki (odpowiedź zgodna ze schematem `Catalog`); API linków nie istnieje (403 dla każdego CN) |
| `ClientTokenAuditTest` | zdarzenie `authentication` z gateway'a dla każdego powodu odrzucenia tokenu C1, tylko pola ze schematu, treść tokenu ani claimy nie trafiają do zdarzenia ani logu, awaria JWKS -> 401 i zdarzenie `jwks_unavailable` (przez HTTP), `typ` inny niż `JWT` -> 401, warianty zapisu ścieżki MCP nie omijają audytu, szum (`/`, `/favicon.ico`, `OPTIONS`) bez zdarzeń |
| `MissingTokenEventLimiterTest` | limit zdarzeń `missing_token` na sekundę, nadmiar liczony w metryce |
| `AuditVectorsTest` | wszystkie wektory `audit-events` 2.2.5 oceniane schematem C8 zgodnie z `expected.valid` |
| `AggregateEndpointTest` | `/mcp` i `/s/<serverId>/mcp` przez HTTP: lista kilku systemów w stałej kolejności, filtr zawęża i niczego nie przyznaje, wywołanie poza filtrem to `not_found_or_denied` z `filter_scope` w audycie, zły filtr (w tym `%zz`, `?=x`, `?%ff=1`) to 400 po sprawdzeniu tokenu i bez gubienia filtra, sesja związana z trasą i filtrem (także `DELETE`, `_meta`, cudza sesja), `GET` 405, `/v/` 404 bez względu na token, metadane `/mcp` ignorują query, wolny serwer pominięty, tabela linków usunięta |
| `EndpointVectorsTest` | wektory `endpoint-filter/` (parse, route, apply, call, call-state, session, session-order) i `endpoint-aggregate/` (list, availability, page, cursor, routing) na klasach, których używa gateway |
| `SaturationTest`, `ConcurrencyLimitFilterTest`, `BoundedRedisQueueTest` | proces gatewaya na stercie 320 MB, 600 wywołań naraz do wolnego systemu przy limicie 20: wszystko poza `ok` to `503` z `Retry-After`, serwer widzi najwyżej 20 wywołań, brak tokenu daje 401, proces żyje; filtr oddaje miejsce także po błędzie; kolejka Redisa ograniczona |
| `HighAvailabilityTest` | dwie instancje jako dwa procesy na jednym Redisie i PostgreSQL: potwierdzenie TOTP zaczęte na A kończy się na B i kod działa raz, sesja, filtr i kursor ważne na obu, Redis wstrzymany -> odmowa (503, `upstream_unavailable`), zabicie instancji w trakcie 240 wywołań kosztuje tylko ponowienie |
| `ReplicatedStoreTest` | `WAIT`: zmiana stanu potwierdzeń potwierdzona przez replikę, odmowa gdy żadna nie potwierdza |
| `PublicEdgeTest`, `PublicEdgeFilterTest` | nosniff, CSP, brak `Set-Cookie` i JSON na ponad 20 odpowiedziach (gniazdo surowe: błędy aplikacji i kontenera, `Accept: text/html`), `Cookie` klienta nie dociera do serwera ani brokera, metadane RFC 9728 na adresie publicznym mimo fałszywego `Host`/`X-Forwarded-*`, metadane tylko dla kształtów endpointów MCP, wyzwanie bez znaków z żądania |
| `ClientCertificateVerifierTest`, `PublicUrlsTest`, `ResourceMetadataTest`, `ServerRegistryTest` | łańcuch, daty i cel certyfikatu klienta; origin publiczny; kształty ścieżek metadanych; rozwiązywanie nazw narzędzi i walidacja konfiguracji |
| `GatewayIntegrationTest` | prawdziwy gateway z IdP, brokerem i serwerem testowym po mTLS: 401 + RFC 9728, sesje i ich właściciel, obie ery protokołu, nagłówki klienta nie docierają do serwera, `credential_required`, `upstream_unavailable` (503 i zerwane połączenie), unieważnienie <= 1 s, TTL, SAN serwera, JWKS tylko na porcie wewnętrznym, audyt zgodny ze schematem C8, brak sekretów w logach; DESTRUCTIVE i UPDATE bez `-write`, poświadczenie spoza ASCII (bez wartości w logu), odpowiedzi brokera spoza C4, wstrzymanie kontenera Redis (cache pomijany, powrót po subskrypcji), tokeny C1 za długie i z `sub` `system:`, limit 1 MiB, `Origin` |

## Uruchomienie lokalne w `mcp-platform-dev` (ws-01)

### Na hoście (sprawdzone 2026-10-28, porty 18700-18703)

Infrastruktura z `make up` (Keycloak, Redis, PostgreSQL, certyfikaty); gateway, atrapa brokera i serwer testowy jako
procesy na hoście, bez zmian w kontenerach środowiska. Gateway: `http://localhost:18700` (klienci MCP, metadane),
`https://localhost:18701` (JWKS C2, actuator, C5 z mTLS); serwer testowy `https://localhost:18702/mcp`; atrapa
brokera `https://localhost:18703`.

```bash
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

Obraz `mcp-gateway:dev` (glibc, bo `cedar-java` nie ma bibliotek dla musl) pasuje do usługi `mcp-gateway`; potrzebuje `MCP_POLICY_*`, `/app/state` jako wolumenu per instancja i `MCP_PUBLIC_URL` na origin proxy
(`http://localhost:${PROXY_PORT}`, nie port gateway'a), `MCP_DB_*` i adresów pozostałych serwerów
(`MCP_SERVER_<SYSTEM>_MCP_URL`, domyślne `https://mcp-<system>.internal:8443/mcp` zgadzają się z aliasami profilu
`m2`). Serwer testowy może zastąpić `mcp-jira` przez `MCP_JIRA_IMAGE=mcp-gateway-test-server:dev`. Tego wariantu
w M2 nie uruchamiałem (STATUS.md).

## CI (`ci/run.sh`, M5-5)

Cała logika jest w `ci/run.sh` (`make ci` wywołuje `verify`): `verify` (kontrola tekstu, `mvnw clean verify` obu modułów, błąd przy zerze
uruchomionych testów), `hygiene`, `image` (obraz `mcp-gateway:<MCP_IMAGE_STAGE>-<sha>` z czystego drzewa, domyślnie `m6`). Błąd kroku to kod wyjścia skryptu, nieznany lub
pusty krok to błąd (2); `ci/self-test.sh` sprawdza to atrapą `mvnw`, która kończy się błędem. `ci/Dockerfile` daje obraz do uruchomienia
bez JDK. Artefakty kontraktów na czystym runnerze: `MCP_MAVEN_REPOSITORY_URL`, `_USER`, `_PASSWORD` (`.ci/settings.xml`). Testy startują
kontenery (PostgreSQL, Redis), więc potrzebny jest dostęp do Dockera.

Nakładki `.gitlab-ci.yml`, `Jenkinsfile`, `.github/workflows/ci.yml` tylko wołają ten skrypt. Granica zaufania: kod zmiany (MR, PR) może zmienić
każdy plik repozytorium, także skrypt i `.ci/settings.xml`, więc plik w gałęzi nie jest w stanie sam egzekwować granicy; egzekwuje ją
system CI. GitLab: zmienne zapisu `MCP_MAVEN_REPOSITORY_USER/PASSWORD` są chronione (tylko gałęzie chronione), zadanie MR dostaje token tylko do odczytu
(`MCP_MAVEN_RO_*`), cache MR jest osobny i tylko do odczytu, a runner MR nie ma gniazda Dockera hosta. Jenkins: poświadczenia i agent z gniazdem
Dockera (etykieta `docker-trusted`) tylko w zadaniu z `main`; zmiana dostaje hygiene i self-test bez gniazda (pełny przebieg po scaleniu);
Jenkinsfile z gałęzi też jest kodem zmiany, więc obowiązuje to tylko, gdy Jenkins bierze Jenkinsfile z gałęzi domyślnej dla zadań z `main`
(multibranch z zaufanym źródłem). GitHub: rejestr z artefaktami `mcp-contracts` czyta `GITHUB_TOKEN` przebiegu (`packages: read`), bez PAT i bez sekretów; PR ma zadanie bez rejestru. Wydanie (`release.yml`) ma trzy joby: build (tylko odczyt), publish (`packages: write`, tylko `docker load` i `docker push`) i release (`contents: write`, tylko `gh release create`). Reszta
izolacji runnerów to M6.

## Struktura

```
pl.aiwcorpo.mcp.gateway
├── admin/     C5: AdminController (katalog), mTLS: ClientCertificateVerifier i filtr CN
├── auth/      C1: GatewayUser, 401 z resource_metadata, PublicUrls, adresy RFC 9728
├── authz/     ToolAuthorizer: CedarToolAuthorizer (ocena `call` z paczki)
├── policy/    PolicyService, BundleFetcher: paczki polityk C7
├── confirm/   C11: ConfirmationRules, ConfirmationService, RedisConfirmationStore
├── activity/  /activity/calls: ActivityStore, ActivityAggregator, ActivityCursor
├── registry/  zatwierdzone manifesty C6, DefinitionCheck, RegistryStore, licznik zmian
├── killswitch/ wyłącznik awaryjny: tabela, pamięć podręczna do 5 s, stan gotowości
├── stream/    strumienie SSE: ToolStreams, ListChangeTracker, UserToolLists
├── edge/      jedna domena: PublicEdgeFilter, WellKnownGuard, błędy tylko JSON
├── audit/     zdarzenia C8 na loggerze AUDIT
├── broker/    C4: BrokerClient, cache, credential.invalidated, token exchange, kontrola /v1/systems
├── config/    właściwości, beany, Spring Security, drugi connector Tomcat
├── jwt/       C2: klucze, wystawca, JWKS, rozdział portów, UUIDv7
├── mcp/       endpoint MCP (obie ery), sesje klientów, tools/list i tools/call, błędy C10
├── server/    serwery: konfiguracja i narzędzia z zatwierdzonego manifestu
├── tls/       mTLS i sprawdzanie SAN serwera
└── upstream/  klient Streamable HTTP do serwerów, sesje per użytkownik
```

Testy obciążeniowe są w `mcp-load-tests`.

## Audyt odrzuconych tokenów: ryzyko zalewu

Zdarzenie `authentication` powstaje dla każdej ścieżki poza znanym szumem (`OPTIONS`, `/`, `/favicon.ico`, `/robots.txt`); lista dopuszczająca ścieżki MCP pomijałaby warianty zapisu (`%73`, `;x=1`, `//`, wielkość liter), które łańcuch security dopasowuje do tras MCP. Żądania bez tokenu nic nie kosztują wołającego, dlatego `missing_token` i `malformed` mają osobne limity po 20 zdarzeń na sekundę na proces; nadmiar zwiększa `mcp_audit_authentication_suppressed_total{component,reason}` i nie trafia do C8. Odrzucone tokeny (zły podpis, wygasły) nie mają limitu: wymagają zdarzenia dla każdego odrzucenia, więc brzeg (nginx `limit_req` per adres) powinien ograniczać ich liczbę.
