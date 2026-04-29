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
- [Functions/Token.cs](Functions/Token.cs): OIDC Token-Exchange fuer Authorization-Code-Grant
- [Functions/RefreshToken.cs](Functions/RefreshToken.cs): Token-Erneuerung
- [Functions/GetPublicKeys.cs](Functions/GetPublicKeys.cs): Bereitstellung von Public Keys als JWKS
- [Services/CTLoginService.cs](Services/CTLoginService.cs): Calls gegen ChurchTools API
- [Services/JWTService.cs](Services/JWTService.cs): JWT-Claims, Signatur, Refresh-Validierung, Key-Lifecycle
- [Services/JWKService.cs](Services/JWKService.cs): Umwandlung gespeicherter Public Keys in JWK
- [Services/UserTokenService.cs](Services/UserTokenService.cs): Speicherung der ChurchTools-Sessionreferenz

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

### 2.5. OIDC Token-Exchange

1. Client sendet `application/x-www-form-urlencoded` an den Endpoint `oidc/token`.
2. Der Dienst validiert `grant_type`, `code`, `code_verifier`, `client_id` und `redirect_uri`.
3. Der Authorization Code wird auf Gueltigkeit, Ablaufzeit und PKCE (`S256`) geprueft.
4. Bei Erfolg wird der Code einmalig verbraucht und ein neues Token-Set zurueckgegeben.

### 3. Public Key Discovery

1. Ein konsumierender Dienst ruft den JWKS-Endpoint auf.
2. Die aktuell gespeicherten Public Keys werden als `keys`-Array zurueckgegeben.
3. Downstream-Systeme koennen damit JWT-Signaturen offline validieren.

## API

Standardmaessig verwendet Azure Functions den Prefix `/api`.

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
- `502 Bad Gateway`: ChurchTools liefert nach Login keine Benutzerdetails

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

Gespeichert werden unter anderem:

- Aktueller Private Key und zugehoeriger Public Key
- Ausgegebene Refresh Tokens inkl. Access-Token-Bindung
- Externe Sessionreferenzen (`st_ref`) fuer ChurchTools Login-Kontext

## Konfiguration

Erforderliche Umgebungsvariablen:

- `AzureWebJobsStorage`: Verbindung zu Azure Storage
- `FUNCTIONS_WORKER_RUNTIME=dotnet-isolated`
- `CT_URL`: Basis-URL der ChurchTools-Instanz

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

## Bekannte Grenzen

- Es wird genau eine ChurchTools-Instanz ueber `CT_URL` adressiert.
- Fallback-Logik bei ChurchTools-/Storage-Ausfall ist nicht enthalten.
- Refresh-Tokens sind nicht fuer langfristige Offline-Sessions ausgelegt.
