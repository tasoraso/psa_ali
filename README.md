# psa_ali
PSA Hunter – Search → URLs → Certs → Validate → DB

# Projektstruktur (Vorschlag)

```
psa-hunter/
├─ .env                          # ENV-Variablen (PSA_TOKEN, PSA_BASE_URL, REQUESTS_CA_BUNDLE)
├─ README.md                     # Doku & How-To
├─ requirements.txt              # Python-Abhängigkeiten
├─ composer.json                 # PHP-Abhängigkeiten
├─ hunter_full.py                # Python: Search → URLs → Certs → Validate → SQLite
├─ psa_public_psacert_cached.php # PHP: PSA-API Cacher/Validator mit SQLite & Logs
│
├─ data/
│  ├─ queries.txt                # Suchbegriffe (eine Zeile = eine Suche)
│  ├─ urls.txt                   # gesammelte URLs (auto gepflegt)
│  └─ certs.txt                  # gefundene Cert-Nummern (auto gepflegt)
│
├─ db/
│  ├─ psa.db                     # SQLite (Vollschema: psa_certs)
│  └─ export_YYYY-MM-DD.csv      # CSV-Exporte (optional)
│
├─ logs/
│  ├─ psa_YYYY-MM-DD.log         # PHP/Guzzle Tageslogs (volle Responses, Header etc.)
│  └─ daily_runner_YYYY-MM-DD.log# PowerShell Runner-Logs
│
├─ scripts/
│  └─ daily_import.ps1           # täglicher Runner (dedupe → import → csv-export)
│
└─ tools/
   ├─ scrape_certs.php           # URLs laden → Cert-Nummern extrahieren → data/certs.txt
   ├─ discover_and_import.php    # Scrape → Validate (Daily-Cap) → DB
   └─ dedupe_normalize_certs.php # certs.txt deduplizieren/normalisieren (beschr. mergen)
```

````markdown
# PSA Hunter – Search → URLs → Certs → Validate → DB

Ein Toolkit, um PSA-Cert-Nummern aus dem offenen Web zu finden, sie optional gegen die PSA Public API zu validieren und in SQLite zu speichern. Windows-freundlich, mit Logs, Dedupe, CSV-Export und einem täglichen Runner.

## Inhalt

- [Features](#features)
- [Voraussetzungen](#voraussetzungen)
- [Setup](#setup)
- [Ordner & Dateien](#ordner--dateien)
- [ENV (.env)](#env-env)
- [Workflows](#workflows)
  - [A) Suchen → URLs → Certs (Python)](#a-suchen--urls--certs-python)
  - [B) Validierung + DB (Python)](#b-validierung--db-python)
  - [C) PSA-API Cache/Validator (PHP)](#c-psa-api-cachevalidator-php)
  - [D) Täglicher Runner (PowerShell)](#d-täglicher-runner-powershell)
  - [E) Dedupe / Normalize (PHP Tool)](#e-dedupe--normalize-php-tool)
- [Tipps](#tipps)
- [Troubleshooting](#troubleshooting)

## Features

- **hunter_full.py** (Python):
  - Sucht via DuckDuckGo (HTML/Lite mit Fallbacks)
  - Extrahiert echte Ziel-URLs (DDG `uddg`-Redirect)
  - Domain-Whitelist, Regex Allow/Deny, `--include-any`
  - Debug-Stats (warum URLs rausfliegen)
  - Scannt Seiten nach Cert-Nummern (`\b\d{7,9}\b`)
  - Optional: validiert fehlende Certs via **PSA Public API** (Daily-Cap), speichert in **SQLite** (Vollschema `psa_certs`)
  - Stabil: certifi-CA, Retries, getrennte Connect/Read-Timeouts, Ctrl+C-sicher (Puffer-Flush)

- **psa_public_psacert_cached.php** (PHP):
  - Fragt PSA-API an (mit Guzzle), cached in SQLite
  - **volle Response-Logs** (Header + Body) mit Monolog
  - Tageslimit, Max-Age, Sleep, CSV-Export, UTF-8
  - Speichert nur **valide** Antworten (Year 4-stellig, Brand/Subject vorhanden)

- **tools/** (PHP):
  - `scrape_certs.php`: URLs laden → Certs extrahieren (ohne API)
  - `discover_and_import.php`: Scrape → Validate → DB mit Daily-Cap
  - `dedupe_normalize_certs.php`: `certs.txt` deduplizieren, Beschreibungen mergen

- **scripts/daily_import.ps1**:
  - Dedupe → Import (PHP) → CSV → alles in Tageslog

## Voraussetzungen

- **Python 3.10+** (unter Windows ok)
- **PHP 8.1+** (CLI)
- **Composer**
- Internetzugang (ggf. Firmen-Proxy/SSL-Inspection beachten)

## Setup

```powershell
# 1) Projekt klonen/erstellen
cd D:\My_Files\ali
mkdir psa-hunter
cd psa-hunter

# 2) Ordnerstruktur anlegen (oder Repo entpacken)
mkdir data, db, logs, scripts, tools

# 3) Python-Dependencies
python -m pip install -r requirements.txt
# (oder direkt)
python -m pip install requests beautifulsoup4 python-dotenv certifi

# 4) PHP-Dependencies
composer install
# (oder)
composer require guzzlehttp/guzzle monolog/monolog vlucas/phpdotenv

# 5) .env anlegen (siehe unten)
notepad .env
````

```powershell
# .env benötigt PSA_TOKEN
python .\hunter_full.py --validate --daily-cap 80 --sleep-ms 250


python hunter_full.py --queries ./data/queries.txt --urls ./data/urls.txt --certs ./data/certs.txt --per-query 50 --max-pages 4 --sleep 1.2 --include-any


python .\hunter_full.py --urls .\data\urls.txt --certs .\data\certs.txt --scan-limit-per-url 0 --scan-sleep 0.8 --connect-timeout 8 --read-timeout 25 --retries 2


python .\hunter_full.py --queries .\data\queries.txt --urls .\data\urls.txt --certs .\data\certs.txt


python .\hunter_full.py --validate --daily-cap 80 --sleep-ms 250
```

