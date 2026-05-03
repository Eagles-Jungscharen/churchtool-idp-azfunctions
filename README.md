# churchtool-idp-azfunctions

Identity Provider (IDP) fuer ChurchTools auf Basis von Azure Functions (.NET Isolated). Das Projekt authentifiziert Benutzer gegen ChurchTools, erstellt signierte JWTs und stellt einen JWKS-Endpunkt fuer die Token-Pruefung bereit.

## Ziel des Projekts

Dieser Dienst uebersetzt ChurchTools-Logins in ein JWT-basiertes Authentifizierungsmodell, damit andere Anwendungen ChurchTools-Benutzer konsistent authentifizieren und autorisieren koennen.

## Architekturueberblick

Das Projekt besteht aus drei Ebenen:

- Functions als HTTP-Einstiegspunkte
- Services fuer ChurchTools-Integration, Token-Erzeugung und Key-Verwaltung
- Models fuer Requests/Responses und Table-Storage-Entitaeten

Wichtige Komponenten:

- [Program.cs](Program.cs): DI-Setup, HttpClient-Registrierung, Table-Client-Registrierung
- [Functions/Authenticate.cs](Functions/Authenticate.cs): Login gegen ChurchTools und Token-Ausgabe
- [Functions/Authorize.cs](Functions/Authorize.cs): OIDC Authorization-Endpunkt, initiiert den Authorization-Code-Flow
- [Functions/Login.cs](Functions/Login.cs): OIDC Login-Endpunkt, verarbeitet Benutzerdaten im Authorization-Code-Flow
- [Functions/Token.cs](Functions/Token.cs): OIDC Token-Exchange fuer Authorization-Code-Grant
- [Functions/RefreshToken.cs](Functions/RefreshToken.cs): Token-Erneuerung
- [Functions/OpenIdConfigurationFunction.cs](Functions/OpenIdConfigurationFunction.cs): OpenID Connect Discovery-Endpoint fuer automatische Client-Konfiguration
- [Functions/GetPublicKeys.cs](Functions/GetPublicKeys.cs): Bereitstellung von Public Keys als JWKS
- [Services/CTLoginService.cs](Services/CTLoginService.cs): Calls gegen ChurchTools API
- [Services/JWTService.cs](Services/JWTService.cs): JWT-Claims, Signatur, Refresh-Validierung, Key-Lifecycle
- [Services/JWKService.cs](Services/JWKService.cs): Umwandlung gespeicherter Public Keys in JWK
- [Services/UserTokenService.cs](Services/UserTokenService.cs): Speicherung der ChurchTools-Sessionreferenz
- [Services/AuthorizationCodeService.cs](Services/AuthorizationCodeService.cs): Erzeugung und Validierung von Authorization Codes
- [Services/AuthorizationRequestService.cs](Services/AuthorizationRequestService.cs): Speicherung und Abruf von Authorization Requests
- [Services/ClientInformationService.cs](Services/ClientInformationService.cs): Verwaltung registrierter OAuth-Clients

## End-to-End Funktionsweise

### 1. Authentifizierung

1. Client sendet Benutzername/Passwort an den Endpoint `authenticate`.
2. Der Dienst fuehrt Login gegen ChurchTools aus.
3. Bei Erfolg werden Benutzerprofil und Gruppen geladen.
4. Gruppen werden in Scopes umgewandelt.
5. Es werden `id_token`, `access_token` und `refresh_token` erzeugt.
6. Das Token-Set wird im OAuth-ueblichen Format zurueckgegeben.

### 2. Token-Refresh

1. Client sendet `refreshToken` im Body und `Authorization: Bearer <access_token>` im Header.
2. Der Dienst prueft, ob Refresh-Token und Access-Token zusammenpassen.
3. Bei Erfolg wird das alte Refresh-Token entfernt und ein neues Token-Set erstellt.

### 2.5. OIDC Authorization-Code-Flow

#### Schritt 1: Authorization Request

1. Client sendet `GET /api/oidc/authorize` mit `response_type=code`, `client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method` (S256) und `state`.
2. Der Dienst validiert die Parameter und prueft `client_id` sowie `redirect_uri` gegen die registrierten Client-Daten.
3. Ein Authorization Request wird gespeichert und der Benutzer wird an die Login-Seite (`LOGIN_CLIENT_URL`) weitergeleitet.

#### Schritt 2: OIDC Login

1. Die Login-Seite sendet Benutzername, Passwort und die `authentication_request_id` an `POST /api/login`.
2. Der Dienst validiert den Authorization Request und prueft, ob er noch gueltig ist (max. 5 Minuten).
3. Bei erfolgreichem ChurchTools-Login werden ein Authorization Code erzeugt und der Browser mit `code` und `state` an die `redirect_uri` weitergeleitet.

#### Schritt 3: Token-Exchange

1. Client sendet `application/x-www-form-urlencoded` an den Endpoint `oidc/token`.
2. Der Dienst validiert `grant_type`, `code`, `code_verifier`, `client_id` und `redirect_uri`.
3. Der Authorization Code wird auf Gueltigkeit, Ablaufzeit (max. 5 Minuten) und PKCE (`S256`) geprueft.
4. Bei Erfolg wird der Code einmalig verbraucht und ein neues Token-Set zurueckgegeben.

### 3. Public Key Discovery

1. Ein konsumierender Dienst ruft den JWKS-Endpoint auf.
2. Die aktuell gespeicherten Public Keys werden als `keys`-Array zurueckgegeben.
3. Downstream-Systeme koennen damit JWT-Signaturen offline validieren.

## API

Standardmaessig verwendet Azure Functions den Prefix `/api`.

### GET /api/oidc/.well-known/openid-configuration

Beschreibung: OpenID Connect Discovery-Endpoint. Liefert Metadaten ueber den Identity Provider gemaess OpenID Connect Discovery 1.0 Spezifikation. Dieser Endpoint ermoeglicht OIDC-Clients die automatische Konfiguration aller Endpoints und unterstuetzten Features.

Erfolg (200):

```json
{
   "issuer": "CT_IDP",
   "authorization_endpoint": "https://<base-url>/api/oidc/authorize",
   "token_endpoint": "https://<base-url>/api/oidc/token",
   "jwks_uri": "https://<base-url>/api/jwks.json",
   "response_types_supported": ["code"],
   "subject_types_supported": ["public"],
   "id_token_signing_alg_values_supported": ["RS256"],
   "grant_types_supported": ["authorization_code"],
   "scopes_supported": ["openid"],
   "claims_supported": ["sub", "iat", "jti", "firstname", "lastname", "email", "st_ref", "scopes"],
   "code_challenge_methods_supported": ["S256"],
   "token_endpoint_auth_methods_supported": ["none"],
   "response_modes_supported": ["query"]
}
```

Hinweis: Die Base-URL in allen Endpoint-URLs wird dynamisch aus der eingehenden Anfrage ermittelt (z.B. `http://localhost:7071` lokal oder `https://your-idp.azurewebsites.net` in Azure).

### POST /api/authenticate

Beschreibung: Fuehrt Login gegen ChurchTools durch und gibt ein neues Token-Set zurueck.

Request:

```json
{
   "username": "<churchtools-user>",
   "password": "<churchtools-password>"
}
```

Erfolg (200):

```json
{
   "id_token": "...",
   "access_token": "...",
   "refresh_token": "...",
   "expires_in": 3600,
   "token_type": "Bearer"
}
```

Typische Fehler:

- `400 Bad Request`: Payload fehlt oder Benutzername/Passwort fehlt
- `401 Unauthorized`: ChurchTools-Login nicht erfolgreich
- `502 Bad Gateway`: ChurchTools liefert nach Login keine Benutzerdetails (ErrorNumber: 2003)

### POST /api/refresh

Beschreibung: Erneuert Tokens auf Basis eines gueltigen Token-Paars.

Header:

```text
Authorization: Bearer <access_token>
```

Request:

```json
{
   "refreshToken": "<refresh-token>"
}
```

Erfolg (200): gleiches Response-Format wie bei `/api/authenticate`.

Typische Fehler:

- `401 Unauthorized`: Authorization Header fehlt/ungueltig
- `400 Bad Request`: Payload oder refreshToken fehlt
- `400 Bad Request`: Kombination aus Refresh- und Access-Token ist ungueltig

### POST /api/oidc/token

Beschreibung: Tauscht einen Authorization Code gegen ein Token-Set im OAuth2-Format aus.

Header:

```text
Content-Type: application/x-www-form-urlencoded
```

Request:

```text
grant_type=authorization_code&code=<authorization-code>&code_verifier=<pkce-verifier>&client_id=<client-id>&redirect_uri=<redirect-uri>
```

Erfolg (200): gleiches Response-Format wie bei `/api/authenticate`.

Typische Fehler:

- `400 Bad Request`: Pflichtparameter fehlen oder `grant_type` ist ungueltig
- `400 Bad Request`: `client_id` oder `redirect_uri` ist ungueltig
- `400 Bad Request`: Authorization Code ist ungueltig/abgelaufen/bereits verbraucht
- `400 Bad Request`: PKCE-Pruefung (`code_verifier`) fehlgeschlagen

### GET /api/oidc/authorize

Beschreibung: Startet den OIDC Authorization-Code-Flow mit PKCE. Validiert Client und Parameter, speichert den Authorization Request und leitet den Benutzer an die Login-Seite weiter.

Query-Parameter:

```text
response_type=code
&client_id=<client-id>
&redirect_uri=<redirect-uri>
&code_challenge=<pkce-challenge>
&code_challenge_method=S256
&state=<state>
```

Erfolg (302): Weiterleitung an `LOGIN_CLIENT_URL?authorization_request_id=<id>`.

Typische Fehler:

- `400 Bad Request`: Pflichtparameter fehlen oder `response_type` ist ungueltig
- `400 Bad Request`: `client_id` oder `redirect_uri` ist ungueltig

### POST /api/login

Beschreibung: Nimmt Benutzerdaten und eine `authentication_request_id` entgegen, authentifiziert gegen ChurchTools und leitet bei Erfolg mit einem Authorization Code an die `redirect_uri` weiter.

Request:

```json
{
   "username": "<churchtools-user>",
   "password": "<churchtools-password>",
   "authentication_request_id": "<authorization-request-id>"
}
```

Erfolg (302): Weiterleitung an `<redirect_uri>?code=<authorization-code>&state=<state>`.

Typische Fehler:

- `400 Bad Request`: Payload fehlt oder Pflichtfelder fehlen
- `400 Bad Request`: `authentication_request_id` ungueltig oder abgelaufen (> 5 Minuten)
- `401 Unauthorized`: ChurchTools-Login nicht erfolgreich
- `502 Bad Gateway`: ChurchTools liefert nach Login keine Benutzerdetails (ErrorNumber: 5006)

### GET /api/jwks.json

Beschreibung: Liefert oeffentliche Schluessel im JWKS-Format.

Erfolg (200):

```json
{
   "keys": [
      {
         "kid": "...",
         "kty": "RSA",
         "e": "...",
         "n": "..."
      }
   ]
}
```

### Client-Verwaltung (Admin)

Die folgenden Endpunkte erfordern Function-Key-Authentifizierung (Query-Parameter `?code=<function_key>` oder Header `x-functions-key: <function_key>`). Sie dienen der administrativen Verwaltung von OAuth-Client-Registrierungen.

#### POST /api/clients

Beschreibung: Erstellt eine neue Client-Registrierung.

Header:

```text
x-functions-key: <function_key>
```

Request:

```json
{
   "name": "Meine Anwendung",
   "owner": "admin@example.com",
   "redirectUris": ["https://example.com/callback"]
}
```

Erfolg (201):

```json
{
   "clientId": "neue Client Id",
   "name": "Meine Anwendung",
   "owner": "admin@example.com",
   "redirectUris": ["https://example.com/callback"]
}
```

Typische Fehler:

- `400 Bad Request`: Pflichtfelder fehlen (clientId, name, owner, redirectUris)
- `400 Bad Request`: RedirectUris enthalten ungültige URIs (müssen mit https:// oder http://localhost/ beginnen)

#### PUT /api/clients/{clientId}

Beschreibung: Aktualisiert eine bestehende Client-Registrierung (partielle Updates möglich).

Header:

```text
x-functions-key: <function_key>
```

Request (alle Felder optional):

```json
{
   "name": "Neuer Name",
   "owner": "neuer-owner@example.com",
   "redirectUris": ["https://example.com/new-callback"]
}
```

Erfolg (200):

```json
{
   "clientId": "my-client",
   "name": "Neuer Name",
   "owner": "neuer-owner@example.com",
   "redirectUris": ["https://example.com/new-callback"]
}
```

Typische Fehler:

- `400 Bad Request`: Kein Feld zum Update angegeben
- `400 Bad Request`: RedirectUris enthalten ungültige URIs
- `404 Not Found`: Client mit der angegebenen clientId nicht gefunden

#### DELETE /api/clients/{clientId}

Beschreibung: Löscht eine Client-Registrierung.

Header:

```text
x-functions-key: <function_key>
```

Erfolg (204): Keine Response-Body.

Typische Fehler:

- `404 Not Found`: Client mit der angegebenen clientId nicht gefunden

#### GET /api/clients

Beschreibung: Listet alle registrierten Clients auf.

Header:

```text
x-functions-key: <function_key>
```

Erfolg (200):

```json
{
   "clients": [
      {
         "clientId": "my-client",
         "name": "Meine Anwendung",
         "owner": "admin@example.com",
         "redirectUris": ["https://example.com/callback"]
      }
   ]
}
```

## Fehlercodes

Alle `400 Bad Request`-Antworten enthalten ein strukturiertes JSON-Objekt mit `error` (Fehlermeldung) und `errorNumber` (eindeutige Nummer):

```json
{
   "error": "Fehlende Pflichtparameter",
   "errorNumber": 1001
}
```

### Authorize (1000-1099)

| Fehlercode | Beschreibung | Endpoint |
|------------|--------------|----------|
| 1001 | Fehlende Pflichtparameter | `GET /api/oidc/authorize` |
| 1002 | response_type muss 'code' enthalten | `GET /api/oidc/authorize` |
| 1003 | Unbekannte Client-ID | `GET /api/oidc/authorize` |
| 1004 | Ungültige redirect_uri | `GET /api/oidc/authorize` |

### Authenticate (2000-2099)

| Fehlercode | Beschreibung | Endpoint |
|------------|--------------|----------|
| 2001 | Kein gültiges Login-Objekt übergeben | `POST /api/authenticate` |
| 2002 | Kein Benutzername oder Passwort übergeben | `POST /api/authenticate` |

### Token (3000-3099)

| Fehlercode | Beschreibung | Endpoint |
|------------|--------------|----------|
| 3001 | Content-Type muss 'application/x-www-form-urlencoded' sein | `POST /api/oidc/token` |
| 3002 | Fehlende Pflichtparameter | `POST /api/oidc/token` |
| 3003 | grant_type muss 'authorization_code' sein | `POST /api/oidc/token` |
| 3004 | Unbekannte Client-ID | `POST /api/oidc/token` |
| 3005 | Ungültige redirect_uri | `POST /api/oidc/token` |
| 3006 | Ungültiger Authorization Code | `POST /api/oidc/token` |
| 3007 | Authorization Code abgelaufen | `POST /api/oidc/token` |
| 3008 | redirect_uri stimmt nicht mit der Authorisierungsanfrage überein | `POST /api/oidc/token` |
| 3009 | Ungültiger code_verifier | `POST /api/oidc/token` |

### RefreshToken (4000-4099)

| Fehlercode | Beschreibung | Endpoint |
|------------|--------------|----------|
| 4001 | Keine Nutzlast verfügbar | `POST /api/refresh` |
| 4002 | Kein refreshToken übermittelt | `POST /api/refresh` |
| 4003 | Refresh und Access Token Kombination ungültig | `POST /api/refresh` |

### Login (5000-5099)

| Fehlercode | Beschreibung | Endpoint |
|------------|--------------|----------|
| 5001 | Kein gültiges Login-Objekt übergeben | `POST /api/login` |
| 5002 | Kein Benutzername oder Passwort übergeben | `POST /api/login` |
| 5003 | Keine AuthenticationRequestId übergeben | `POST /api/login` |
| 5004 | Ungültige AuthenticationRequestId | `POST /api/login` |
| 5005 | AuthorizationRequest abgelaufen | `POST /api/login` |

### Client Management (6000-6099)

| Fehlercode | Beschreibung | Endpoint |
|------------|--------------|----------|
| 6001 | Kein gültiges Request-Objekt übergeben | `POST /api/clients`, `PUT /api/clients/{clientId}` |
| 6002 | ClientId fehlt oder ist leer | `POST /api/clients` |
| 6003 | Name fehlt oder ist leer | `POST /api/clients` |
| 6004 | Owner fehlt oder ist leer | `POST /api/clients` |
| 6005 | RedirectUris fehlt oder ist leer | `POST /api/clients`, `PUT /api/clients/{clientId}` |
| 6006 | Mindestens ein Feld muss für Update angegeben werden | `PUT /api/clients/{clientId}` |
| 6007 | Client nicht gefunden | `PUT /api/clients/{clientId}`, `DELETE /api/clients/{clientId}` |

## Claims- und Scope-Modell

Die erzeugten JWTs enthalten unter anderem folgende Claims:

- `iat` und `jti`
- `firstname`, `lastname`, `email`
- `st_ref` als Referenz auf gespeicherte Login-Daten
- Mehrfach-Claim `scopes` fuer Gruppenberechtigungen

Scope-Ableitung:

- ChurchTools-Gruppen werden als `ct_group_<domainIdentifier>` in das Token uebernommen.

## Schluessel- und Token-Lifecycle

- Access Token Laufzeit: 3600 Sekunden
- Private Key Laufzeit: 43200 Sekunden
- Refresh Tokens sind an den Access Token gebunden und werden nach erfolgreicher Nutzung entfernt

Hinweis: Die Schluessel liegen in Azure Table Storage und werden bei Bedarf neu erzeugt.

## Persistenz in Azure Table Storage

Verwendete Tabellen:

- `PublicKeyTable`
- `PrivateKeyTable`
- `RefreshTokenTable`
- `UserLoginTokensTable`
- `AuthorizationRequestTable`
- `AuthorizationCodeTable`
- `ClientInformationTable`

Gespeichert werden unter anderem:

- Aktueller Private Key und zugehoeriger Public Key
- Ausgegebene Refresh Tokens inkl. Access-Token-Bindung
- Externe Sessionreferenzen (`st_ref`) fuer ChurchTools Login-Kontext
- Laufende Authorization Requests inkl. PKCE-Challenge und State
- Einmalig verwendbare Authorization Codes inkl. Benutzerdaten und Ablaufzeit
- Registrierte OAuth-Clients mit erlaubten `redirect_uri`-Werten

## Konfiguration

Erforderliche Umgebungsvariablen:

- `AzureWebJobsStorage`: Verbindung zu Azure Storage
- `FUNCTIONS_WORKER_RUNTIME=dotnet-isolated`
- `CT_URL`: Basis-URL der ChurchTools-Instanz
- `LOGIN_CLIENT_URL`: URL der Login-Frontend-Anwendung fuer den OIDC Authorization-Code-Flow

Lokale Entwicklung erfolgt ueber [local.settings.json](local.settings.json).

## Lokaler Betrieb

Voraussetzungen:

- .NET SDK (gem. [churchtool-idp-azfunctions.csproj](churchtool-idp-azfunctions.csproj))
- Azure Functions Core Tools
- Zugriff auf eine ChurchTools-Instanz
- Gueltige Storage-Verbindung

Build:

```bash
dotnet build
```

Start:

```bash
func start
```

## Logging und Betrieb

- Application-Insights-Sampling ist in [host.json](host.json) aktiviert.
- Wichtige Ablaufpunkte (Login, Refresh, Key-Laden) werden geloggt.
- Der Dienst arbeitet upstream-abhaengig von ChurchTools und Azure Storage.

## Sicherheitshinweise

- Der Dienst ist fuer HTTPS-Betrieb vorgesehen.
- Zugangsdaten werden nicht persistiert.
- Refresh Tokens sind nicht dauerhaft, sondern an bestehende Token-Kombinationen gebunden.
- Fuer Produktion sollte CORS in [local.settings.json](local.settings.json) nicht offen (`*`) betrieben werden.
- Admin-Endpunkte zur Client-Verwaltung (`/api/clients`) erfordern Function Keys und sind fuer administrative Zwecke vorgesehen.

## Bekannte Grenzen

- Es wird genau eine ChurchTools-Instanz ueber `CT_URL` adressiert.
- Fallback-Logik bei ChurchTools-/Storage-Ausfall ist nicht enthalten.
- Refresh-Tokens sind nicht fuer langfristige Offline-Sessions ausgelegt.
