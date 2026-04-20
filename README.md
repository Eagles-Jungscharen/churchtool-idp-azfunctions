# churchtool-idp-azfunctions

Ein Identity Provider (IDP) für [ChurchTools](https://church.tools/), der als Azure Functions läuft und signierte JWT-Tokens generiert.

## Übersicht

Dieses Projekt fungiert als Brücke zwischen der ChurchTools-Authentifizierung und einem standardisierten OAuth/JWT-basierten Authentifizierungsmodell. Es ermöglicht anderen Anwendungen, ChurchTools-Benutzer zu authentifizieren und deren Berechtigungen über JWT-Tokens zu nutzen.

## Funktionsweise

### Authentifizierung

1. Ein Benutzer sendet seine ChurchTools-Anmeldedaten (Benutzername/Passwort) an den IDP
2. Der IDP authentifiziert den Benutzer gegen die ChurchTools-API
3. Bei erfolgreicher Anmeldung werden folgende Tokens erstellt:
   - **ID Token**: Enthält Benutzerinformationen (Vorname, Nachname, E-Mail)
   - **Access Token**: Enthält die Berechtigungen basierend auf den ChurchTools-Gruppenmitgliedschaften
   - **Refresh Token**: Ermöglicht die Erneuerung abgelaufener Tokens

### Berechtigungen (Scopes)

Die Gruppenmitgliedschaften des Benutzers in ChurchTools werden automatisch als Scopes in die Tokens übernommen. So können andere Anwendungen feingranulare Zugriffskontrollen basierend auf den ChurchTools-Gruppen implementieren.

### Token-Verifizierung

Der IDP stellt einen öffentlichen Endpunkt bereit, über den andere Services die öffentlichen Schlüssel abrufen können. Damit können diese die Signatur der JWT-Tokens verifizieren, ohne den IDP bei jeder Anfrage kontaktieren zu müssen.

### Token-Erneuerung

Abgelaufene Access Tokens können mittels des Refresh Tokens erneuert werden, ohne dass sich der Benutzer erneut anmelden muss.

## Anwendungsfälle

- **Single Sign-On**: Benutzer melden sich einmal mit ihren ChurchTools-Zugangsdaten an und können auf mehrere verbundene Anwendungen zugreifen
- **API-Absicherung**: Eigene APIs können die JWT-Tokens zur Authentifizierung und Autorisierung nutzen
- **Gruppenbezogene Berechtigungen**: Zugriff auf Funktionen kann basierend auf ChurchTools-Gruppenmitgliedschaften gesteuert werden
