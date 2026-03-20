# FIDO2 / WebAuthn Integration Analysis for HestiaCP

> Ergänzende Analyse zur architektonischen und sicherheitstechnischen Bestandsaufnahme.  
> Untersucht, welche WebAuthn-Modi für HestiaCP sinnvoll sind, ob die exec/sudo-Infrastruktur
> zwingend benötigt wird, und wie sich Credentials ohne Datenbank persistent speichern lassen.

---

## 1. FIDO2 / WebAuthn — Einsatzformen im Überblick

WebAuthn (Web Authentication API, W3C-Standard) ist die Browser-Seite des FIDO2-Standards.  
Es gibt drei relevante Einsatzformen, die sich in Sicherheitsniveau und UX unterscheiden:

| Modus | Authenticator-Typ | Typisches Gerät | User-Verification (UV) |
|---|---|---|---|
| **Roaming Authenticator** | CTAP2 via USB / NFC / BLE | YubiKey, FIDO2-Stick | optional oder required |
| **Platform Authenticator** | Eingebaut ins Gerät | Touch ID, Windows Hello, Face ID | immer required |
| **Passkey (Discoverable Credential)** | Platform *oder* Roaming mit Sync | iCloud Keychain, Google Password Manager | immer required |

### Signifikante Unterschiede

- **Roaming Authenticator** (z. B. YubiKey): Der private Schlüssel verlässt das Gerät nie;
  sehr hohe Sicherheit; der Nutzer muss das physische Token besitzen.
- **Platform Authenticator**: An ein bestimmtes Gerät gebunden; bequem, aber bei Geräteverlust
  muss ein Recovery-Weg existieren.
- **Passkey**: Credentials werden geräteübergreifend synchronisiert (Cloud-Sync durch den
  Betriebssystem-Anbieter); einfachste UX, aber der private Schlüssel lebt in einem
  Cloud-Keystore.

### Empfohlener Modus für HestiaCP

Die naheliegendste Einführungsform ist **WebAuthn als optionaler zweiter Faktor** (2FA),
vollständig parallel zum vorhandenen TOTP:

```
Schritt 1: Benutzername eingeben
Schritt 2: Passwort eingeben
Schritt 3a: TOTP-Code eingeben  — wie bisher
Schritt 3b: WebAuthn-Assertion — neu, als Alternative zu TOTP
```

Ein vollständig passwortloser Login (*Passkey-only*) wäre ein größerer Umbau und würde den
bestehenden `v-check-user-hash`/`/etc/shadow`-Pfad komplett ersetzen.  
Das ist mittelfristig möglich, aber als erster Schritt nicht empfehlenswert.

---

## 2. Passt WebAuthn zur Architektur von HestiaCP?

### 2.1 Bestandsaufnahme der Authentication-Pipeline

Die aktuelle 2FA-Implementierung (TOTP) folgt diesem Muster:

```
Browser (PHP hestiaweb-User)
  → exec("sudo /usr/local/hestia/bin/v-check-user-2fa $user $token")
      → als root: source $HESTIA/data/users/$user/user.conf  (liest $TWOFA)
      → als root: $HESTIA_PHP web/inc/2fa/check.php "$TWOFA" "$token"
          → PHP-Library robthree/twofactorauth verifies TOTP in-memory
      ← exit 0 (ok) oder exit 9 (fail)
  ← return_var
```

**Wichtige Beobachtung:** Die kryptografische TOTP-Prüfung selbst braucht kein root —
sie findet in einer reinen PHP-Bibliothek statt. Root wird nur benötigt, um `user.conf`
zu lesen, weil `hestiaweb` keinen direkten Dateizugriff auf `$HESTIA/data/users/` hat
(Verzeichnis: Mode 750, Eigentümer root).

Für WebAuthn wäre die Struktur analog:

```
Browser (PHP hestiaweb-User)
  → [Challenge erzeugen und in PHP-Session speichern]   ← kein sudo nötig
  → [JS: navigator.credentials.get() im Browser]        ← kein sudo nötig
  → exec("sudo /usr/local/hestia/bin/v-check-user-webauthn $user $assertion_json")
      → als root: liest webauthn.conf (stored public keys, sign count)
      → als root: $HESTIA_PHP web/inc/webauthn/verify.php "$credentials" "$assertion" "$challenge"
          → PHP-Library verifiziert Signatur in-memory
      ← exit 0 / exit 9
  ← return_var
```

### 2.2 Passt das Muster?

Ja — WebAuthn als 2FA fügt sich ohne Bruch in die bestehende Architektur ein:

- **Neue `v-*`-Skripte** übernehmen die privilegierten Operationen (read/write `webauthn.conf`).
- **PHP-seitige Crypto** (Signaturprüfung) läuft in einem Library-Call ohne root-Bedarf.
- **Challenge-State** lebt in der PHP-Session (`$HESTIA/data/sessions/`), die bereits
  `hestiaweb:hestiaweb` gehört — kein sudo erforderlich.
- **Login-Templates** bekommen eine neue Variante für den WebAuthn-Schritt (wie `login_2.php`
  für TOTP, würde `login_webauthn.php` hinzukommen).

---

## 3. Benötigt WebAuthn die exec/sudo-Logik?

**Kurze Antwort: Ja — für den Zugriff auf Credential-Daten zwingend.**

### 3.1 Warum sudo nicht wegzulassen ist

`hestiaweb` ist der unprivilegierte PHP-FPM-Prozess. Er hat **keinen direkten Lesezugriff**
auf `$HESTIA/data/users/`:

```
/usr/local/hestia/data/users/   Mode 750, Owner: root
  admin/
    user.conf        (TWOFA-Secret plaintext, Passwort-MD5, …)
    webauthn.conf    (würde public keys + sign count enthalten)
```

Selbst wenn die kryptografische Verifikation vollständig in PHP stattfindet, muss
**mindestens** die gespeicherte Public Key Credential aus `webauthn.conf` gelesen werden —
und das benötigt root (via sudo → `v-list-user-webauthn`).

Gleiches gilt für:
- **Registrierung** (Schreiben der neuen Credential in `webauthn.conf`)
- **Sign-Count-Update** nach jedem erfolgreichen Login (Replay-Schutz)
- **Löschen** einer Credential (Key-Verwaltung im UI)

### 3.2 Was ohne sudo machbar wäre

Drei Teile des WebAuthn-Flows kommen **ohne sudo** aus:

| Schritt | sudo nötig? | Begründung |
|---|---|---|
| Challenge generieren & in Session speichern | ✗ Nein | Session-Dir gehört hestiaweb |
| `navigator.credentials.get()` im Browser | ✗ Nein | reines Browser-JS / WebAuthn-API |
| Signatur kryptografisch verifizieren | ✗ Nein | reine PHP-Library-Operation |
| Stored Credential aus `webauthn.conf` lesen | ✓ Ja | File in root-owned Dir |
| Sign Count nach Login aktualisieren | ✓ Ja | Schreiben in root-owned Dir |
| Neue Credential registrieren | ✓ Ja | Schreiben in root-owned Dir |
| Bestehende Credential löschen | ✓ Ja | Löschen in root-owned Dir |

Eine Implementierung **ohne sudo** wäre nur möglich, wenn die WebAuthn-Credential-Dateien
außerhalb von `$HESTIA/data/users/` abgelegt und für `hestiaweb` direkt zugänglich wären.
Das würde jedoch das bestehende Sicherheitsmodell brechen: `hestiaweb` hätte dann direkten
Lesezugriff auf Authentifizierungsgeheimnisse, ohne dass der sudo-Audit-Trail greift.

**Empfehlung:** sudo-Logik beibehalten. Die exec/sudo-Grenze ist bewusst und korrekt.

---

## 4. Datenbank — Wird eine benötigt?

### 4.1 Aktueller Befund: Keine interne DB in HestiaCP

HestiaCP verwendet **keinerlei eigene Datenbank** für seine operationalen Daten.
Alle Systemdaten liegen in strukturierten Flat Files:

```
$HESTIA/data/
  users/
    admin/
      user.conf      ← Nutzerprofil, TWOFA-Secret, Limits
      web.conf       ← Web-Domain-Einträge
      dns.conf       ← DNS-Zonen
      db.conf        ← Metadaten verwalteter Datenbanken
      mail.conf      ← Mail-Domain-Einträge
      cron.conf      ← Cron-Jobs
  sessions/          ← PHP-Sessions als Dateien (kein Session-DB)
  queue/             ← Restart-Queues als Pipe-Dateien
```

Die MySQL- und PostgreSQL-Installationen, die Hestia *verwaltet*, sind reine **Nutzer-Ressourcen**
(für Websites der Hosting-Kunden). Hestia selbst schreibt nie in eine eigene DB.

### 4.2 Implikationen für WebAuthn

Für WebAuthn-Credentials braucht es **keine Datenbank** — das Flat-File-Modell ist ausreichend:

```
$HESTIA/data/users/$user/webauthn.conf
```

Format (analog zu den bestehenden `.conf`-Dateien, eine Zeile pro Key):

```
CREDENTIAL_ID='base64url-encoded-id' NAME='YubiKey 5' PUBLIC_KEY='cbor-encoded-key' SIGN_COUNT='42' TRANSPORT='usb' DATE='2026-01-15'
CREDENTIAL_ID='base64url-encoded-id-2' NAME='iPhone (Face ID)' PUBLIC_KEY='cbor-encoded-key-2' SIGN_COUNT='7' TRANSPORT='internal' DATE='2026-01-20'
```

Ein Nutzer kann mehrere Credentials registrieren (mehrere Hardware-Keys, mehrere Geräte).
Die mehrzeilige Flat-File-Struktur ist genau das Muster, das Hestia überall einsetzt.

### 4.3 Kein DB-Konsultieren bei sonstigen Änderungen

Die Frage, ob bei *anderen* Hestia-Operationen (Web-Domain anlegen, Benutzer erstellen etc.)
eine Datenbank angesprochen wird, ist eindeutig zu verneinen:
- `v-add-web-domain`, `v-add-user`, `v-add-database` etc. schreiben allesamt nur in
  Flat Files (`web.conf`, `user.conf`) und führen OS-level-Befehle aus (nginx-Konfig,
  useradd, mysql-Client).
- Es gibt keine ORM-Schicht, keinen DB-Migrations-Engine, keine Connection-Pool-Konfiguration
  für Hestia-interne Daten.

---

## 5. Konkrete Implementierungsskizze

### 5.1 Neue `v-*`-Kommandos

```bash
v-add-user-webauthn    USER CREDENTIAL_JSON NAME      # Registrierung abschließen
v-list-user-webauthn   USER [FORMAT]                  # Alle registrierten Keys
v-delete-user-webauthn USER CREDENTIAL_ID             # Key entfernen
v-check-user-webauthn  USER ASSERTION_JSON CHALLENGE  # Assertion verifizieren + Count updaten
```

Keines dieser Kommandos benötigt Netzwerk oder DB-Zugriff — nur Dateizugriff auf
`$HESTIA/data/users/$user/webauthn.conf`.

### 5.2 PHP-Bibliothek

Die Bibliothek `lbuchs/webauthn` (MIT-Lizenz, keine externen Abhängigkeiten) würde in
`web/inc/vendor/` via Composer eingebunden:

```json
// web/inc/composer.json
{
    "require": {
        "phpmailer/phpmailer": "7.0.2",
        "hestiacp/phpquoteshellarg": "1.1.0",
        "robthree/twofactorauth": "3.0.3",
        "lbuchs/webauthn": "^2.2"
    }
}
```

### 5.3 Neue PHP-Endpunkte

```
web/webauthn/
  register/
    challenge.php   GET  → Challenge erzeugen, in Session speichern, als JSON zurückgeben
    complete.php    POST → Attestation entgegennehmen, via sudo v-add-user-webauthn speichern
  authenticate/
    challenge.php   GET  → Challenge erzeugen, in Session speichern
    complete.php    POST → Assertion verifizieren via sudo v-check-user-webauthn
```

### 5.4 Login-Flow-Erweiterung

```
[login_2.php]
  Zeigt:
  - TOTP-Eingabefeld (wie bisher)
  - ODER: "Mit Security Key anmelden"-Button (neu)
      → JS: navigator.credentials.get({challenge: ..., rpId: ...})
      → POST auf /webauthn/authenticate/complete.php
      → Redirect auf /login/ mit gesetzter Session
```

### 5.5 Session-basiertes Challenge-Handling (kein sudo)

```php
// /webauthn/authenticate/challenge.php
$challenge = random_bytes(32);
$_SESSION['webauthn_challenge'] = base64_encode($challenge);
$_SESSION['webauthn_challenge_ts'] = time();  // Ablauf nach 60 s

header('Content-Type: application/json');
echo json_encode([
    'challenge' => base64url_encode($challenge),
    'rpId'      => $_SERVER['HTTP_HOST'],
    'timeout'   => 60000,
]);
```

Die Challenge lebt ausschließlich in der PHP-Session — kein sudo, kein DB, kein tmpfile.

---

## 6. Sicherheitsbewertung der Integration

| Aspekt | TOTP (aktuell) | WebAuthn (geplant) |
|---|---|---|
| Phishing-Resistenz | ✗ Nein (Code kann abgefangen werden) | ✓ Ja (Challenge ist origin-bound) |
| Secret-Exposition | ✗ TWOFA plaintext in user.conf | ✓ Nur Public Key gespeichert; privater Schlüssel verlässt Authenticator nie |
| Replay-Angriffe | Zeitfenster (30 s) | Sign-Count schützt gegen Replay |
| Recovery bei Verlust | Schwach (TWOFA-Secret = Reset-Code) | Backup-Keys oder Email-OOB möglich |
| Sudo-Umfang | Gleich wie jetzt | Gleich wie jetzt; kein neuer Angriffspfad |
| Browser-Kompatibilität | Alle Browser | Alle modernen Browser (Chrome 67+, Firefox 60+, Safari 14+) |

---

## 7. Fazit

1. **Empfohlener Einstiegsmodus**: WebAuthn als optionaler zweiter Faktor (zusätzlich zu TOTP),
   analog zur bestehenden 2FA-Architektur.
2. **exec/sudo ist zwingend notwendig** für alle Credential-Lese/Schreib-Operationen, da
   `hestiaweb` keinen direkten Zugriff auf `$HESTIA/data/users/` hat. Das ist korrekt und
   soll so bleiben.
3. **Kein Datenbankzugriff benötigt** — weder jetzt noch nach einer WebAuthn-Integration.
   Das Flat-File-Modell (`webauthn.conf` pro User) reicht vollständig aus.
4. **Challenge-State** (der einzige Teil des Flows, der wirklich kein sudo braucht) lebt
   sauber in der PHP-Session, die `hestiaweb` bereits direkt schreiben darf.
5. **Implementierungsaufwand**: ~4 neue `v-*`-Bash-Skripte, 1 neue PHP-Bibliothek via Composer,
   ~4 neue PHP-Endpunkte, 1 angepasstes Login-Template und ein neues `webauthn.conf`-Format.
   Keine Datenbankmigrationen, keine Änderungen am Sicherheitsmodell.
