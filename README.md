# 🛡️ SecureScope - Network Security Audit Tool

SecureScope ist ein webbasiertes Netzwerk-Sicherheitsaudit-Tool, das Port-Scanning, Ergebnisanalyse und Risikobewertung in einer übersichtlichen Benutzeroberfläche vereint.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

---

## 📋 Features

### Authentifizierung & Sicherheit
- Admin-Login mit Session-Management
- Passwort-Hashing mit bcrypt
- Rate-Limiting für Login-Versuche (max. 5 in 15 Minuten)
- CSRF-Protection für alle API-Endpunkte
- Sichere Session-Cookies (httpOnly, sameSite)
- Automatischer Session-Timeout nach 30 Minuten
- Erzwungene Passwortänderung beim ersten Login

### Port-Scanning
- **Quick Scan** – Top 100 Ports
- **Standard Scan** – Top 1000 Ports
- **Full Scan** – Alle 65.535 Ports
- **Custom Scan** – Benutzerdefinierte Ports
- Unterstützung für einzelne IPs und CIDR-Bereiche (bis /24)
- Echtzeit-Fortschrittsanzeige via Server-Sent Events (SSE)
- Abbruchmöglichkeit für laufende Scans
- Beschränkung auf private IP-Bereiche (RFC 1918) standardmäßig

### Ergebnisse & Analyse
- Farbkodierte Risikobewertung (Sicher / Warnung / Kritisch)
- Export in CSV, JSON und PDF
- Scan-Historie mit Filtern (Datum, Typ, Status, Ziel)
- Vergleichsfunktion zwischen zwei Scans
- Paginierung für große Ergebnismengen

### UI/UX
- Modernes, responsives Dashboard
- Dark Mode / Light Mode
- Toast-Benachrichtigungen
- Loading-Spinner und Fortschrittsbalken
- Mobile-friendly Design

---

## 🚀 Schnellstart

### Voraussetzungen

- **Node.js** >= 18.0.0
- **npm** >= 9.0.0
- **Nmap** (muss im System-PATH verfügbar sein)
- **Git** (für ExploitDB Sync)
- **curl** & **unzip** (für CVE/Exploit Sync)

### Installation

```bash
# Repository klonen
git clone https://github.com/SecureScope/main.git
cd securescope

# Dependencies installieren
npm install

# Umgebungsvariablen konfigurieren
cp .env.example .env
# .env nach Bedarf anpassen

# Server starten
npm start
```

### Erster Login

1. Öffnen Sie `http://localhost:3000` im Browser
2. Melden Sie sich mit den Standard-Zugangsdaten an:
   - **Benutzername:** `admin`
   - **Passwort:** `admin`
3. Sie werden aufgefordert, das Passwort zu ändern
4. Nach der Passwortänderung gelangen Sie zum Dashboard

---

## 🐳 Docker

### Mit Docker Compose (empfohlen)

```bash
# Bauen und Starten im Hintergrund
docker-compose up -d --build

# Logs anzeigen
docker-compose logs -f securescope

# Stoppen
docker-compose down
```

### Mit Docker direkt

```bash
# Image bauen
docker build -t securescope .

# Container starten
docker run -d \
  --name securescope \
  -p 3000:3000 \
  -e SESSION_SECRET=ihr_geheimes_passwort \
  -e CSRF_SECRET=ihr_csrf_geheimnis \
  -v securescope_data:/app/database \
  -v securescope_logs:/app/logs \
  securescope
```

---

## ⚙️ Konfiguration

### Umgebungsvariablen

| Variable | Beschreibung | Standard |
|---|---|---|
| `PORT` | Server-Port | `3000` |
| `SESSION_SECRET` | Geheimnis für Session-Verschlüsselung | (erforderlich) |
| `CSRF_SECRET` | Geheimnis für CSRF-Token | (erforderlich) |
| `DATABASE_PATH` | Pfad zur SQLite-Datenbank | `./database/securescope.db` |
| `LOG_LEVEL` | Log-Level (error, warn, info, debug) | `info` |
| `NODE_ENV` | Umgebung (development, production) | `development` |
| `COOKIE_SECURE` | Erzwingt Secure-Cookies (true/false) | `true` in Prod |
| `SCAN_TIMEOUT` | Maximale Scan-Dauer in ms | `300000` (5 Min.) |
| `MAX_CONCURRENT_SCANS` | Max. gleichzeitige Scans | `3` |
| `ALLOW_EXTERNAL_SCANS` | Externe IPs scannen erlauben | `false` |

---

## 📡 API-Endpunkte

### Authentifizierung

| Methode | Endpunkt | Beschreibung |
|---|---|---|
| `POST` | `/api/auth/login` | Benutzer-Login |
| `POST` | `/api/auth/logout` | Benutzer-Logout |
| `GET` | `/api/auth/status` | Session-Status prüfen |
| `POST` | `/api/auth/change-password` | Passwort ändern |

### Scan-Operationen

| Methode | Endpunkt | Beschreibung |
|---|---|---|
| `POST` | `/api/scan/start` | Neuen Scan starten |
| `GET` | `/api/scan/status/:id` | Scan-Status abrufen |
| `POST` | `/api/scan/stop/:id` | Scan abbrechen |
| `GET` | `/api/scan/results/:id` | Scan-Ergebnisse (paginiert) |
| `GET` | `/api/scan/history` | Scan-Historie mit Filtern |
| `GET` | `/api/scan/compare` | Zwei Scans vergleichen |
| `GET` | `/api/scan/export/:id` | Ergebnisse exportieren |
| `GET` | `/api/scan/events` | SSE-Stream für Live-Updates |

### Beispiel: Scan starten

```bash
curl -X POST http://localhost:3000/api/scan/start \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <token>" \
  -b "securescope.sid=<session>" \
  -d '{
    "target": "192.168.1.1",
    "scanType": "quick"
  }'
```

---

## 📁 Projektstruktur

```
securescope/
├── server.js                 # Server-Einstiegspunkt
├── app.js                    # Express-Applikation
├── package.json              # Dependencies & Scripts
├── .env                      # Umgebungsvariablen
├── .env.example              # Beispiel-Konfiguration
├── Dockerfile                # Docker-Image
├── docker-compose.yml        # Docker Compose
├── config/
│   └── database.js           # SQLite-Konfiguration & Init
├── database/
│   ├── securescope.db        # SQLite-Datenbank (auto-generiert)
│   └── schema/               # SQL-Schema-Definitionen
│       ├── 01_auth.sql
│       ├── 02_core_scans.sql
│       └── ...
├── middleware/
│   ├── auth.js               # Auth, Session-Timeout, CSRF
│   └── rateLimit.js          # Rate-Limiting
├── routes/
│   ├── auth.js               # Auth-API-Routen
│   └── scan.js               # Scan-API-Routen & SSE
├── services/
│   ├── logger.js             # Winston Logger mit Rotation
│   ├── scanner.js            # Port-Scan-Engine (nmap)
│   ├── nmapParser.js         # Nmap XML Parser
│   ├── cveService.js         # CVE Matching Logic
│   └── userService.js        # Benutzerverwaltung
├── public/
│   ├── index.html            # Login-Seite
│   ├── dashboard.html        # Dashboard
│   ├── css/
│   │   └── style.css         # Komplettes Stylesheet
│   └── js/
│       ├── login.js          # Login-Logik
│       └── dashboard.js      # Dashboard-Logik
├── logs/                     # Log-Dateien (auto-generiert)
└── tests/
    └── auth.test.js          # Grundlegende Tests
```

---

## 🔒 Sicherheitshinweise

### Wichtig

1. **Ändern Sie die Standard-Zugangsdaten** sofort nach dem ersten Login
2. **Setzen Sie sichere Secrets** für `SESSION_SECRET` und `CSRF_SECRET` in der Produktion
3. **Externe Scans** sind standardmäßig deaktiviert – aktivieren Sie `ALLOW_EXTERNAL_SCANS` nur wenn nötig
4. **Scannen Sie nur Netzwerke**, für die Sie eine Berechtigung haben
5. **Verwenden Sie HTTPS** in der Produktion (z.B. mit einem Reverse Proxy wie nginx)

### Risikobewertung der Ports

| Farbe | Risiko | Beispiele |
|---|---|---|
| 🟢 Grün | Sicher/Erwartet | SSH (22), HTTPS (443), DNS (53) |
| 🟡 Gelb | Prüfenswert | HTTP (80), SMTP (25), POP3 (110) |
| 🔴 Rot | Kritisch | Telnet (23), FTP (21), SMB (445), RDP (3389) |

---

## 🧪 Tests

```bash
# Tests ausführen
npm test

# Tests mit Coverage
npm test -- --coverage

# Tests im Watch-Modus
npm run test:watch
```

---

## 🔧 Troubleshooting

### Server startet nicht

1. Prüfen Sie, ob Port 3000 frei ist: `lsof -i :3000`
2. Prüfen Sie die Node.js-Version: `node --version` (>= 18 erforderlich)
3. Löschen Sie `node_modules` und installieren Sie neu: `rm -rf node_modules && npm install`

### Datenbank-Fehler

1. Löschen Sie die Datenbank: `rm database/securescope.db`
2. Starten Sie den Server neu – die Datenbank wird automatisch erstellt

### Scan liefert keine Ergebnisse

1. Prüfen Sie, ob die Ziel-IP erreichbar ist: `ping <IP>`
2. Prüfen Sie die Firewall-Einstellungen
3. Versuchen Sie einen Quick Scan statt Full Scan
4. Prüfen Sie die Logs: `cat logs/securescope-*.log`

### Session-Probleme

1. Löschen Sie die Browser-Cookies für localhost
2. Starten Sie den Server neu
3. Prüfen Sie, ob `SESSION_SECRET` gesetzt ist

---

## 📝 Entwicklung

```bash
# Development-Modus mit Auto-Reload
npm run dev

# Logs beobachten
tail -f logs/securescope-*.log
```

---

## 🗺️ Roadmap (nach MVP)

- [ ] Vulnerability-Datenbank-Integration
- [ ] Scheduled Scans (Cronjobs)
- [ ] Email-Benachrichtigungen
- [ ] Multi-User-Support
- [ ] RBAC (Role-Based Access Control)
- [ ] Report-Generator (PDF/HTML)
- [ ] API-Dokumentation (Swagger/OpenAPI)

---

## 📄 Lizenz

MIT License – siehe [LICENSE](LICENSE) Datei.

---

**SecureScope** – Network Security Audit Tool v1.0  
Entwickelt mit ❤️ für Netzwerksicherheit