"""
MalScan Backend — cybersecurity file/behavior scanner
=======================================================

Wat dit WEL doet (echte, uitlegbare technieken):
  - Hash-matching tegen een lokale database van bekende malware-hashes (MD5/SHA256)
  - Entropie-analyse (detecteert packing/encryptie, veelgebruikt door malware om
    signature-detectie te omzeilen)
  - String-/patroonanalyse (verdachte API-namen, PowerShell-obfuscatie, macro-indicatoren)
  - PE-header-inspectie voor Windows-executables (verdachte sections, imports)
  - Optionele VirusTotal-lookup (vereist eigen API-key van de gebruiker)
  - Een simpel regel-gebaseerd risk-scoring-systeem (YARA-achtig, maar in Python)

Wat dit NIET doet (en ook geen enkele tool eerlijk kan beloven):
  - Onbekende zero-day exploits met zekerheid detecteren. Wat je hier krijgt is
    HEURISTIEK: gedrag/kenmerken die vaker bij malware voorkomen. Dat levert
    "verdacht" op, nooit een garantie.

Installatie:
    pip install flask flask-cors requests

Starten:
    python app.py
    -> luistert op http://localhost:5000
"""

import hashlib
import io
import math
import os
import re
import struct
import uuid
from collections import Counter
from datetime import datetime, timezone

from flask import Flask, jsonify, request, render_template, send_file
from flask_cors import CORS

import forensics
from flask_cors import CORS

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)  # staat cross-origin toe (handig als je de frontend ooit los host)

PORT = 5777

# In-memory opslag van forensische rapporten (per case-id), zodat de
# PDF-downloadroute het HTML-rapport kan hergenereren zonder het bestand
# opnieuw te hoeven uploaden. Voor productiegebruik: vervang dit door een
# echte database of tijdelijke bestandsopslag met een retentiebeleid.
FORENSIC_CASES = {}


@app.route("/", methods=["GET"])
def index():
    """Serveert index.html (die op zijn beurt /static/style.css en /static/script.js laadt)."""
    return render_template("index.html")

# ---------------------------------------------------------------------------
# 1. BEKENDE-MALWARE-HASHDATABASE
# ---------------------------------------------------------------------------
# In productie: koppel dit aan een echte feed (bijv. MalwareBazaar API,
# VirusTotal, of je eigen threat-intel-platform). Dit is een minimale
# lokale demo-database met een paar publiek gedocumenteerde test-hashes.
KNOWN_MALWARE_HASHES = {
    # EICAR test-file (industrie-standaard, ONGEVAARLIJKE test-"malware")
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "name": "EICAR-Test-File",
        "family": "test-signature",
        "severity": "info",
    },
}

# ---------------------------------------------------------------------------
# 2. VERDACHTE STRING-/PATROONREGELS
# ---------------------------------------------------------------------------
# Elke regel = (naam, regex, gewicht in risk-score, categorie)
SUSPICIOUS_PATTERNS = [
    # --- PowerShell / scripting obfuscatie & evasion ---
    ("powershell_encoded_cmd", rb"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", 25, "obfuscation"),
    ("powershell_downloadstring", rb"(?i)downloadstring|invoke-webrequest|iwr\s", 20, "network"),
    ("powershell_bypass_execpolicy", rb"(?i)-executionpolicy\s+bypass", 20, "evasion"),
    ("powershell_hidden_window", rb"(?i)-windowstyle\s+hidden|-w\s+hidden", 15, "evasion"),
    ("shellcode_marker", rb"\x90{8,}", 15, "exploit"),  # NOP-sled

    # --- Process injection / RAT-achtig gedrag ---
    ("suspicious_winapi_combo", rb"(?i)VirtualAlloc.{0,200}WriteProcessMemory.{0,200}CreateRemoteThread", 35, "process-injection"),
    ("suspicious_winapi_hollowing", rb"(?i)NtUnmapViewOfSection|ZwUnmapViewOfSection", 30, "process-injection"),
    ("keylogger_api", rb"(?i)GetAsyncKeyState|SetWindowsHookEx", 25, "spyware"),
    ("screenshot_api", rb"(?i)BitBlt.{0,100}CreateCompatibleBitmap", 15, "spyware"),
    ("webcam_mic_access", rb"(?i)CoCreateInstance.{0,100}(CLSID_VideoInputDeviceCategory|waveInOpen)", 20, "spyware"),

    # --- Macro / Office-documenten ---
    ("office_macro_autoopen", rb"(?i)AutoOpen|Document_Open|AutoExec|Workbook_Open", 15, "macro"),
    ("office_macro_shell", rb"(?i)Shell\(|CreateObject\(\"WScript\.Shell\"\)", 20, "macro"),
    ("office_macro_download", rb"(?i)CreateObject\(\"MSXML2\.|URLDownloadToFile|\.Open\s*\"GET\"", 25, "network"),
    ("office_macro_process_run", rb"(?i)Environ\(\"(TEMP|APPDATA)\"\)|Shell\(.{0,80}(powershell|cmd\.exe|wscript)", 25, "macro"),
    ("office_macro_obfuscation", rb"(?i)Chr\(\d+\)\s*&\s*Chr\(\d+\)|StrReverse\(", 15, "macro"),
    ("office_macro_autoclose", rb"(?i)AutoClose|Document_Close", 8, "macro"),
    ("office_ole_marker", rb"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 5, "macro"),  # OLE2 compound file magic bytes
    ("office_vba_project", rb"(?i)VBA/|_VBA_PROJECT|Macros/vbaProject", 10, "macro"),
    ("office_dde_field", rb"(?i)DDEAUTO|DDE\s+", 25, "macro"),

    # --- Persistence ---
    ("registry_run_key", rb"(?i)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 15, "persistence"),
    ("scheduled_task", rb"(?i)schtasks\s+/create|Register-ScheduledTask", 15, "persistence"),
    ("startup_folder", rb"(?i)\\Start Menu\\Programs\\Startup", 12, "persistence"),

    # --- Obfuscatie algemeen ---
    ("base64_large_blob", rb"[A-Za-z0-9+/]{200,}={0,2}", 10, "obfuscation"),

    # --- Ransomware ---
    ("known_ransomware_ext", rb"(?i)\.locked\b|\.encrypted\b|README_TO_DECRYPT|HOW_TO_DECRYPT|DECRYPT_INSTRUCTIONS", 30, "ransomware"),
    ("ransomware_crypto_api", rb"(?i)CryptEncrypt|CryptGenKey.{0,100}CryptEncrypt", 20, "ransomware"),
    ("shadow_copy_delete", rb"(?i)vssadmin\s+delete\s+shadows|wbadmin\s+delete", 30, "ransomware"),

    # --- Netwerk / C2 / exfiltratie ---
    ("suspicious_url_shortener", rb"(?i)bit\.ly|tinyurl\.com|t\.co/", 5, "network"),
    ("hardcoded_ip_c2", rb"(?i)(http|ftp)s?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 15, "network"),
    ("tor_onion_address", rb"(?i)[a-z2-7]{16,56}\.onion", 20, "network"),
    ("discord_webhook", rb"(?i)discord(app)?\.com/api/webhooks/", 20, "network"),
    ("ftp_exfil", rb"(?i)ftp\.SendFile|StorFile", 15, "exfiltration"),

    # --- Credential theft ---
    ("browser_credential_path", rb"(?i)Login Data|AppData\\Local\\Google\\Chrome\\User Data", 20, "credential-theft"),
    ("mimikatz_marker", rb"(?i)sekurlsa|mimikatz|lsadump", 40, "credential-theft"),

    # --- Anti-analyse / evasion ---
    ("anti_debug_check", rb"(?i)IsDebuggerPresent|CheckRemoteDebuggerPresent", 15, "evasion"),
    ("vm_detection", rb"(?i)VMware|VBox|VirtualBox|Sandboxie|SbieDll", 15, "evasion"),
    ("sleep_evasion", rb"(?i)Sleep\(\s*[3-9]\d{4,}", 10, "evasion"),  # lange sleep = sandbox-ontwijking
]

MAX_UPLOAD_SIZE = 25 * 1024 * 1024  # 25MB veiligheidslimiet voor deze demo


# ---------------------------------------------------------------------------
# HULPFUNCTIES
# ---------------------------------------------------------------------------

def compute_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    """
    Berekent Shannon-entropie (0-8 bits/byte).
    Hoge entropie (>7.2) wijst vaak op packing/encryptie/compressie —
    een klassieke techniek om signature-scanners te omzeilen.
    Let op: legitieme comprimeerde bestanden (zip, jpg) hebben óók hoge
    entropie, dus dit is een indicator, geen bewijs.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def scan_patterns(data: bytes) -> list:
    findings = []
    for name, pattern, weight, category in SUSPICIOUS_PATTERNS:
        matches = re.findall(pattern, data)
        if matches:
            findings.append({
                "rule": name,
                "category": category,
                "weight": weight,
                "match_count": len(matches),
            })
    return findings


def inspect_pe_header(data: bytes) -> dict | None:
    """
    Minimale PE (Windows executable) header-inspectie.
    Checkt: geldige MZ/PE-marker, aantal sections, verdachte section-namen,
    en of het entry point buiten de eerste section valt (packing-indicator).
    """
    if len(data) < 64 or data[:2] != b"MZ":
        return None

    try:
        pe_offset = struct.unpack("<I", data[60:64])[0]
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return None

        num_sections = struct.unpack("<H", data[pe_offset + 6:pe_offset + 8])[0]
        section_table_offset = pe_offset + 24 + 224  # standaard optional header size (32-bit)

        section_names = []
        suspicious_sections = {"upx", "packed", "aspack", ".vmp", ".themida"}
        found_suspicious = []

        offset = section_table_offset
        for _ in range(min(num_sections, 20)):
            if offset + 40 > len(data):
                break
            raw_name = data[offset:offset + 8].rstrip(b"\x00").decode(errors="ignore").lower()
            section_names.append(raw_name)
            if any(s in raw_name for s in suspicious_sections):
                found_suspicious.append(raw_name)
            offset += 40

        return {
            "valid_pe": True,
            "num_sections": num_sections,
            "section_names": section_names,
            "suspicious_sections": found_suspicious,
        }
    except (struct.error, IndexError):
        return {"valid_pe": True, "parse_error": "header truncated of onbekend formaat"}


def detect_office_macro(data: bytes) -> dict | None:
    """
    Aparte, gerichte check voor Office-documenten (doc/xls/ppt of hun
    xml-gebaseerde varianten). OLE2-bestanden beginnen met een vaste
    magic-byte-reeks; xml-gebaseerde (docx/xlsx) zijn eigenlijk zip-bestanden
    (beginnen met 'PK') met een vbaProject.bin erin.
    """
    is_ole2 = data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    is_zip_based = data[:2] == b"PK"
    has_vba_marker = b"vbaProject" in data or b"VBA" in data[:2000] or b"_VBA_PROJECT" in data

    if not (is_ole2 or (is_zip_based and has_vba_marker)):
        return None

    doc_type = "Legacy Office-document (OLE2: .doc/.xls/.ppt)" if is_ole2 else "Modern Office-document (.docx/.xlsm/.pptm) met macro's"

    return {
        "is_office_document": True,
        "format": doc_type,
        "contains_vba_project": has_vba_marker or is_ole2,
    }


# ---------------------------------------------------------------------------
# 3. CLASSIFICATIE-ENGINE
# ---------------------------------------------------------------------------
# Kijkt naar WELKE categorieën samen voorkomen en leidt daar een concreet
# malware-type/familie-label uit af. Dit is nog steeds heuristiek (geen
# vervanging voor een echte reverse-engineering-analyse), maar geeft een
# veel specifieker antwoord dan alleen "verdacht" of "malicious".
CLASSIFICATION_RULES = [
    # (label, vereiste categorieën (allemaal moeten voorkomen), beschrijving)
    (
        "Ransomware",
        {"ransomware"},
        "Bestanden worden mogelijk versleuteld en/of back-ups (schaduwkopieën) verwijderd, gecombineerd met een losgeld-boodschap. Doel: bestanden gijzelen voor losgeld.",
    ),
    (
        "Macro-dropper (Office → payload)",
        {"macro", "network"},
        "Een Office-document met een macro die bij openen automatisch iets van internet download en uitvoert. Klassieke eerste stap van een infectieketen (phishing-bijlage).",
    ),
    (
        "Macro-malware (lokaal, geen download)",
        {"macro"},
        "Een Office-document met verdachte macro-functionaliteit (auto-uitvoeren, shell-commando's, obfuscatie), maar zonder duidelijke downloadstap gevonden. Kan nog steeds schadelijke acties lokaal uitvoeren.",
    ),
    (
        "RAT / Remote Access Trojan",
        {"process-injection", "network"},
        "Injecteert code in andere processen én communiceert met een extern adres. Typisch voor tools die een aanvaller op afstand controle geven over het systeem.",
    ),
    (
        "Spyware / Keylogger",
        {"spyware"},
        "Bevat functionaliteit om toetsaanslagen, schermafbeeldingen of camera/microfoon-toegang te registreren. Doel: stiekem gegevens verzamelen.",
    ),
    (
        "Credential Stealer / Infostealer",
        {"credential-theft"},
        "Zoekt naar opgeslagen wachtwoorden (browsers) of bevat bekende credential-dumping-tooling. Doel: inloggegevens buitmaken.",
    ),
    (
        "Trojan Downloader/Dropper",
        {"network", "obfuscation"},
        "Verborgen/versleutelde code die verbinding maakt met internet — kenmerkend voor een 'dropper' die de eigenlijke payload pas na uitvoering ophaalt.",
    ),
    (
        "Data-exfiltratie-tool",
        {"exfiltration"},
        "Bevat functionaliteit om bestanden actief te versturen naar een extern adres (bijv. via FTP).",
    ),
    (
        "Persistente achtergrond-malware",
        {"persistence", "evasion"},
        "Nestelt zich in autostart-mechanismen en probeert detectie/sandboxes te omzeilen — wijst op malware die lang onopgemerkt actief wil blijven.",
    ),
    (
        "Gepackte/verborgen executable",
        {"obfuscation", "evasion"},
        "Sterk geobfusceerde code die actief detectie probeert te ontwijken. Het exacte doel is zonder verdere reverse-engineering niet vast te stellen, maar dit gedrag is zelden legitiem.",
    ),
]


def classify_malware(pattern_findings: list, entropy: float, pe_info: dict | None, office_info: dict | None) -> dict:
    """
    Leidt een concreet type/familie af uit de gevonden categorieën.
    Retourneert de best passende classificatie(s), gesorteerd op hoeveel
    van de vereiste categorieën matchen (specifiekere match = hoger relevant).
    """
    found_categories = {f["category"] for f in pattern_findings}
    matches = []

    for label, required_categories, description in CLASSIFICATION_RULES:
        if required_categories.issubset(found_categories):
            matches.append({
                "type": label,
                "matched_categories": sorted(required_categories),
                "description": description,
                "specificity": len(required_categories),
            })

    # Sorteer: meest specifieke match (meeste categorieën) eerst
    matches.sort(key=lambda m: m["specificity"], reverse=True)

    # Filter overlappende, minder specifieke matches eruit als een specifiekere
    # match dezelfde categorieën al volledig dekt
    filtered = []
    covered = set()
    for m in matches:
        cat_set = frozenset(m["matched_categories"])
        if not any(cat_set.issubset(c) for c in covered):
            filtered.append(m)
            covered.add(cat_set)

    packing_note = None
    if entropy >= 7.5 and not filtered:
        packing_note = (
            "Geen specifiek gedrag herkend, maar de zeer hoge entropie wijst op "
            "packing of encryptie — een techniek die zowel door legitieme software "
            "(installers) als door malware wordt gebruikt om de echte inhoud te verbergen."
        )

    return {
        "classifications": filtered,
        "office_document": office_info,
        "packing_note": packing_note,
        "categories_found": sorted(found_categories),
    }


def calculate_risk_score(hash_hit: dict | None, entropy: float, pattern_findings: list, pe_info: dict | None) -> dict:
    score = 0
    reasons = []

    if hash_hit:
        score += 100
        reasons.append(f"Bekende malware-hash match: {hash_hit['name']} ({hash_hit['family']})")

    if entropy >= 7.5:
        score += 20
        reasons.append(f"Zeer hoge entropie ({entropy}/8) — mogelijk gepakt/versleuteld")
    elif entropy >= 7.0:
        score += 10
        reasons.append(f"Verhoogde entropie ({entropy}/8)")

    for f in pattern_findings:
        score += f["weight"]
        reasons.append(f"Patroon '{f['rule']}' ({f['category']}) — {f['match_count']}x gevonden")

    if pe_info and pe_info.get("suspicious_sections"):
        score += 25
        reasons.append(f"Verdachte PE-sections: {', '.join(pe_info['suspicious_sections'])}")

    score = min(score, 100)

    if score >= 70:
        verdict = "malicious"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {"score": score, "verdict": verdict, "reasons": reasons}


# ---------------------------------------------------------------------------
# API ROUTES
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})


@app.route("/api/scan", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "Geen bestand meegestuurd (field 'file' verwacht)"}), 400

    uploaded = request.files["file"]
    data = uploaded.read()

    if len(data) > MAX_UPLOAD_SIZE:
        return jsonify({"error": f"Bestand te groot (max {MAX_UPLOAD_SIZE // (1024*1024)}MB voor deze demo)"}), 413

    hashes = compute_hashes(data)
    hash_hit = KNOWN_MALWARE_HASHES.get(hashes["sha256"])
    entropy = shannon_entropy(data)
    pattern_findings = scan_patterns(data)
    pe_info = inspect_pe_header(data)
    office_info = detect_office_macro(data)
    classification = classify_malware(pattern_findings, entropy, pe_info, office_info)
    risk = calculate_risk_score(hash_hit, entropy, pattern_findings, pe_info)

    return jsonify({
        "filename": uploaded.filename,
        "size_bytes": len(data),
        "hashes": hashes,
        "known_hash_match": hash_hit,
        "entropy": entropy,
        "pattern_findings": pattern_findings,
        "pe_info": pe_info,
        "classification": classification,
        "risk": risk,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": (
            "Dit is een heuristische scan. Een lage score betekent niet dat een "
            "bestand veilig is; het betekent dat deze specifieke regels niets "
            "vonden. De classificatie is een educated guess op basis van "
            "patroonherkenning, geen bevestigde malware-familie-identificatie "
            "(dat vereist reverse engineering). Gebruik dit naast, niet in "
            "plaats van, een professionele antivirus/EDR-oplossing."
        ),
    })


@app.route("/api/forensic-scan", methods=["POST"])
def forensic_scan():
    """
    Voert een volledige forensische analyse uit en genereert een
    incident-response-rapport (HTML, met een aparte route voor PDF-export).

    Optionele form-velden: 'analyst' (naam van de onderzoeker), 'case_id'
    (eigen dossiernummer — anders wordt er automatisch één gegenereerd).
    """
    if "file" not in request.files:
        return jsonify({"error": "Geen bestand meegestuurd (field 'file' verwacht)"}), 400

    uploaded = request.files["file"]
    data = uploaded.read()

    if len(data) > MAX_UPLOAD_SIZE:
        return jsonify({"error": f"Bestand te groot (max {MAX_UPLOAD_SIZE // (1024*1024)}MB voor deze demo)"}), 413

    analyst = request.form.get("analyst", "").strip() or None
    case_id_input = request.form.get("case_id", "").strip() or None

    # --- Chain of custody start ---
    coc = forensics.ChainOfCustody(case_id=case_id_input, analyst=analyst)
    hashes = compute_hashes(data)
    coc.evidence_received(uploaded.filename, hashes["sha256"], len(data))

    # --- Basisanalyse (hergebruik van bestaande logica) ---
    coc.analysis_step("Hash-matching tegen bekende-malware-database uitgevoerd.")
    hash_hit = KNOWN_MALWARE_HASHES.get(hashes["sha256"])

    coc.analysis_step("Shannon-entropie berekend over volledig bestand.")
    entropy = shannon_entropy(data)

    coc.analysis_step(f"Patroonherkenning uitgevoerd ({len(SUSPICIOUS_PATTERNS)} regels).")
    pattern_findings = scan_patterns(data)

    coc.analysis_step("PE-header geïnspecteerd (indien van toepassing).")
    pe_info = inspect_pe_header(data)

    office_info = detect_office_macro(data)
    if office_info:
        coc.analysis_step(f"Office-documentstructuur herkend: {office_info['format']}.")

    # --- Diepere forensische technieken ---
    coc.analysis_step("PE compiler-timestamp geëxtraheerd voor tijdlijnreconstructie.")
    pe_timestamp = forensics.extract_pe_timestamp(data)

    coc.analysis_step("Digitale handtekening gecontroleerd op aanwezigheid.")
    signature_info = forensics.check_digital_signature(data)

    coc.analysis_step("Entropie per PE-section berekend.")
    section_entropy = forensics.per_section_entropy(data)

    coc.analysis_step(f"Strings geëxtraheerd (min. lengte 6 tekens) en IOC's geclassificeerd.")
    strings_info = forensics.extract_strings(data)

    classification = classify_malware(pattern_findings, entropy, pe_info, office_info)
    risk = calculate_risk_score(hash_hit, entropy, pattern_findings, pe_info)

    evidence_received_at = coc.entries[1]["timestamp"]  # tweede entry = evidence_received
    timeline = forensics.build_timeline(pe_timestamp, evidence_received_at)

    # --- Integriteitscontrole: hash na analyse moet identiek zijn ---
    hashes_after = compute_hashes(data)
    coc.integrity_check(hashes_after["sha256"], hashes["sha256"])
    coc.report_generated()

    file_type_note = "Windows PE-executable" if pe_info else (
        office_info["format"] if office_info else "Onbekend/generiek binair of tekstbestand"
    )

    report_context = {
        "case_id": coc.case_id,
        "analyst": coc.analyst,
        "report_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "filename": uploaded.filename,
        "size_bytes": len(data),
        "sha256": hashes["sha256"],
        "sha1": hashes["sha1"],
        "md5": hashes["md5"],
        "file_type_note": file_type_note,
        "known_hash_match": hash_hit,
        "coc_entries": coc.as_list(),
        "timeline": timeline,
        "pe_timestamp": pe_timestamp,
        "pe_info": pe_info,
        "section_entropy": section_entropy,
        "signature_info": signature_info,
        "office_document": office_info,
        "pattern_findings": pattern_findings,
        "total_rules": len(SUSPICIOUS_PATTERNS),
        "strings_info": strings_info,
        "classifications": classification["classifications"],
        "verdict": risk["verdict"],
        "verdict_label": risk["verdict"].upper(),
        "risk_score": risk["score"],
        "pattern_count": len(pattern_findings),
        "category_count": len(classification["categories_found"]),
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }

    html_report = render_template("forensic_report.html", **report_context)

    # Bewaar in-memory zodat de PDF-route dit kan hergenereren
    FORENSIC_CASES[coc.case_id] = html_report

    return jsonify({
        "case_id": coc.case_id,
        "html_report": html_report,
        "pdf_url": f"/api/forensic-report/{coc.case_id}.pdf",
        "risk": risk,
        "classification": classification,
    })


@app.route("/api/forensic-report/<case_id>.pdf", methods=["GET"])
def forensic_report_pdf(case_id):
    html_report = FORENSIC_CASES.get(case_id)
    if not html_report:
        return jsonify({"error": "Onbekend case-ID, of de server is herstart sinds het rapport werd gegenereerd."}), 404

    pdf_bytes = forensics.render_html_to_pdf(html_report)
    if pdf_bytes is None:
        return jsonify({
            "error": (
                "PDF-generatie mislukt: wkhtmltopdf is niet gevonden of gaf een fout. "
                "Installeer het met 'apt install wkhtmltopdf' (Linux) of download van "
                "wkhtmltopdf.org (Windows/Mac). Het HTML-rapport is nog steeds beschikbaar."
            )
        }), 500

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"forensic-report-{case_id}.pdf",
    )


if __name__ == "__main__":
    print(f"MalScan draait op http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=True)
