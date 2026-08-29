# MalScan — Heuristische malware-scanner & forensisch rapportagetool

Eén Flask-app (frontend + backend + PDF-rapportage) die bestanden analyseert
op verdachte kenmerken en een incident-response-rapport genereert. Alles
draait lokaal op één poort (**5777**) — er wordt niets naar externe servers
gestuurd.

Dit is een **defensief security-hulpmiddel**: het analyseert bestanden om te
bepalen of ze verdacht zijn. Het bevat geen exploit-code, geen malware, en
voert nooit het gescande bestand uit.

## Wat dit doet

1. **Hash-matching** — SHA256/MD5 tegen een database van bekende malware.
2. **Entropie-analyse** — totaal én per PE-section; hoge entropie wijst op
   packing/encryptie.
3. **Patroon-/stringdetectie** — 30+ regex-regels: PowerShell-obfuscatie,
   macro's, ransomware, RAT-gedrag, credential-theft, C2-communicatie, etc.
4. **PE-header-inspectie** — sections, compiler-timestamp, digitale
   handtekening-aanwezigheid.
5. **Classificatie-engine** — labelt een waarschijnlijk malware-type
   (Ransomware, Macro-dropper, RAT, Spyware, Infostealer, ...) op basis van
   combinaties van gevonden kenmerken.
6. **Forensisch rapport** — genereert een chain-of-custody-log, tijdlijn,
   IOC-extractie (URL's, IP's, e-mailadressen, registry-sleutels) en een
   volledig incident-response-rapport, exporteerbaar als HTML of PDF.

## Wat dit NIET is

- **Geen zero-day-detector.** Onbekende exploits met zekerheid herkennen is
  een onopgelost probleem in de hele industrie. Deze tool signaleert
  *verdacht gedrag*, geen garanties.
- **Geen vervanging voor professionele forensiek.** De classificatie is
  heuristiek (educated guess op basis van patronen), geen bevestigde
  malware-familie-identificatie. Voor dat laatste: reverse engineering
  (Ghidra/IDA) of dynamische sandbox-analyse (Any.run, Hybrid Analysis).
- **Geen dynamische analyse.** Deze tool voert het gescande bestand nooit
  uit — alle analyse is statisch (leest bytes, opent nooit als proces).

## Installatie

```bash
git clone <jouw-repo-url>
cd malscan-backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Voor PDF-rapporten heb je ook het systeempakket `wkhtmltopdf` nodig:
```bash
# Ubuntu/Debian
sudo apt install wkhtmltopdf
# macOS
brew install --cask wkhtmltopdf
# Windows: installer van https://wkhtmltopdf.org/downloads.html
```

Starten:
```bash
python app.py
```

Open **http://localhost:5777** in je browser.

## Bestandsstructuur

```
malscan-backend/
├── app.py                      ← Flask-app: routes, scanlogica, classificatie
├── forensics.py                ← chain-of-custody, PE-forensiek, strings/IOC-extractie
├── requirements.txt
├── LICENSE
├── .gitignore
├── templates/
│   ├── index.html               ← dashboard
│   └── forensic_report.html     ← rapport-template (HTML + PDF-bron)
└── static/
    ├── style.css
    └── script.js
```

## API-endpoints

| Endpoint | Methode | Beschrijving |
|---|---|---|
| `/` | GET | Dashboard |
| `/api/health` | GET | Status-check |
| `/api/scan` | POST | Snelle scan → JSON met risk-score + classificatie |
| `/api/forensic-scan` | POST | Volledige forensische analyse → JSON + HTML-rapport. Optionele form-velden: `analyst`, `case_id` |
| `/api/forensic-report/<case_id>.pdf` | GET | Download het rapport als PDF |

## Verantwoord gebruik

- Scan onbekende/verdachte bestanden altijd in een geïsoleerde omgeving
  (VM zonder netwerktoegang) — deze tool leest alleen bytes, maar het
  besturingssysteem eromheen kan bij het aanraken van een bestand al
  actie ondernemen (bijv. preview-handlers, auto-run).
- Voeg nooit echte malware-samples toe aan deze repository. De
  `.gitignore` sluit veelvoorkomende binary-extensies uit; houd dat zo aan.
- De classificatie en risk-score zijn hulpmiddelen voor triage, geen
  eindoordeel. Gebruik dit naast, niet in plaats van, professionele
  EDR/antivirus-software en (indien nodig) een erkende forensisch
  onderzoeker.
- Dit project is bedoeld voor defensief gebruik: eigen bestanden
  onderzoeken, security-onderwijs, en interne incident response.

## Licentie

MIT — zie [LICENSE](LICENSE).
