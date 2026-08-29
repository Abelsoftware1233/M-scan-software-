"""
MalScan Forensics — module voor incident-response-rapportage
================================================================

Dit bestand voegt een FORENSISCHE laag toe bovenop de heuristische scanner
in app.py. Het verschil: forensiek gaat om reproduceerbaarheid, integriteit
van het bewijs, en het strikt scheiden van FEITEN (wat is er in het bestand
gevonden) van INTERPRETATIE (wat zou dat kunnen betekenen).

Bevat:
  - Chain-of-custody log (elke stap in het onderzoek met timestamp + hash)
  - PE compiler-timestamp-extractie (wanneer is de executable gebouwd)
  - Digitale handtekening-check (is het bestand ondertekend, door wie)
  - Strings-extractie (leesbare tekst uit binary — bron van IOC's)
  - Sectie-per-sectie entropie (i.p.v. alleen het totaal)
  - Tijdlijn-reconstructie uit alle gevonden timestamps

Wat dit NIET is:
  - Geen vervanging voor Volatility (memory forensics), Autopsy (disk
    forensics), of een gecertificeerd forensisch pakket met audit-trail
    die in de rechtbank is getoetst.
  - De classificatie/interpretatie-secties in het rapport zijn en blijven
    heuristisch — het rapport labelt dit expliciet zodat het niet als
    "bewezen conclusie" wordt gelezen.

Installatie extra dependency voor PDF-export:
    (gebruikt wkhtmltopdf via subprocess, geen extra pip-package nodig
    als wkhtmltopdf al op het systeem staat: apt install wkhtmltopdf)
"""

import hashlib
import re
import struct
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# CHAIN OF CUSTODY
# ---------------------------------------------------------------------------

class ChainOfCustody:
    """
    Logt elke actie die op het bewijsmateriaal wordt uitgevoerd, met
    timestamp en een hash-verificatie zodat je achteraf kunt aantonen dat
    het originele bestand niet is aangepast tijdens het onderzoek.

    In een echte forensische workflow zou dit log ook analist-identiteit,
    fysieke locatie van het bewijs, en overdrachtsmomenten bevatten — die
    velden staan hier als invulbare parameters klaar.
    """

    def __init__(self, case_id: str | None = None, analyst: str | None = None):
        self.case_id = case_id or f"CASE-{uuid.uuid4().hex[:8].upper()}"
        self.analyst = analyst or "onbekend (niet opgegeven)"
        self.entries = []
        self._log("case_opened", f"Onderzoek gestart door {self.analyst}")

    def _log(self, action: str, detail: str, evidence_hash: str | None = None):
        self.entries.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "detail": detail,
            "evidence_sha256": evidence_hash,
        })

    def evidence_received(self, filename: str, sha256: str, size_bytes: int):
        self._log(
            "evidence_received",
            f"Bestand '{filename}' ontvangen ({size_bytes} bytes). "
            f"SHA-256 vastgelegd als integriteits-referentie.",
            sha256,
        )

    def analysis_step(self, description: str):
        self._log("analysis_performed", description)

    def integrity_check(self, sha256_now: str, sha256_original: str) -> bool:
        intact = sha256_now == sha256_original
        self._log(
            "integrity_verification",
            "Bevestigd: bewijsmateriaal ongewijzigd sinds ontvangst." if intact
            else "WAARSCHUWING: hash komt niet overeen met origineel — bewijs mogelijk gewijzigd!",
            sha256_now,
        )
        return intact

    def report_generated(self):
        self._log("report_generated", "Forensisch rapport gegenereerd.")

    def as_list(self) -> list:
        return self.entries


# ---------------------------------------------------------------------------
# DIEPERE PE-ANALYSE (compiler-timestamp, digitale handtekening)
# ---------------------------------------------------------------------------

def extract_pe_timestamp(data: bytes) -> dict | None:
    """
    Leest de compiler-timestamp uit de PE-header (COFF File Header).
    Dit is het tijdstip dat de compiler in het bestand heeft geschreven
    tijdens het bouwen — nuttig voor tijdlijn-reconstructie, maar LET OP:
    dit veld kan getruct/vervalst worden door de malware-auteur en is dus
    een indicator, geen garantie.
    """
    if len(data) < 64 or data[:2] != b"MZ":
        return None
    try:
        pe_offset = struct.unpack("<I", data[60:64])[0]
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return None
        timestamp_offset = pe_offset + 8
        raw_timestamp = struct.unpack("<I", data[timestamp_offset:timestamp_offset + 4])[0]

        if raw_timestamp == 0:
            return {"raw": 0, "parsed": None, "suspicious": False, "note": "Geen timestamp aanwezig (0)."}

        try:
            dt = datetime.fromtimestamp(raw_timestamp, tz=timezone.utc)
            now = datetime.now(timezone.utc)
            suspicious = dt.year < 2000 or dt > now
            return {
                "raw": raw_timestamp,
                "parsed": dt.isoformat(),
                "suspicious": suspicious,
                "note": (
                    "Timestamp ligt in de toekomst of vóór 2000 — vaak een teken dat "
                    "dit veld handmatig is aangepast om analyse te bemoeilijken."
                    if suspicious else
                    "Timestamp valt binnen een plausibel bereik (geen garantie voor echtheid)."
                ),
            }
        except (ValueError, OSError, OverflowError):
            return {"raw": raw_timestamp, "parsed": None, "suspicious": True, "note": "Timestamp-waarde is ongeldig/corrupt."}
    except (struct.error, IndexError):
        return None


def check_digital_signature(data: bytes) -> dict:
    """
    Basale check op de aanwezigheid van een Authenticode-handtekening in
    een PE-bestand. Dit checkt ALLEEN of er een handtekeningblok aanwezig
    is (via de Security Directory entry in de Optional Header) — het
    verifieert NIET de geldigheid of het certificaat zelf (dat vereist
    een volledige X.509-chain-validatie, wat buiten deze tool valt).

    Voor een echte handtekeningverificatie: gebruik `signtool verify` op
    Windows of `osslsigncode verify` op Linux.
    """
    if len(data) < 64 or data[:2] != b"MZ":
        return {"applicable": False, "note": "Geen PE-executable, handtekeningcheck niet van toepassing."}

    try:
        pe_offset = struct.unpack("<I", data[60:64])[0]
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return {"applicable": False, "note": "Geen geldige PE-header."}

        magic_offset = pe_offset + 24
        magic = struct.unpack("<H", data[magic_offset:magic_offset + 2])[0]
        is_pe32_plus = magic == 0x20B

        security_dir_offset = magic_offset + (128 if is_pe32_plus else 112)
        cert_table_addr, cert_table_size = struct.unpack(
            "<II", data[security_dir_offset:security_dir_offset + 8]
        )

        if cert_table_size == 0:
            return {
                "applicable": True,
                "signed": False,
                "note": "Geen digitale handtekening aanwezig. Onafhankelijke/onbekende software wordt vaak niet ondertekend — dit alleen is geen bewijs van kwaadaardigheid, maar wél een ontbrekende vertrouwensindicator.",
            }
        else:
            return {
                "applicable": True,
                "signed": True,
                "cert_table_size_bytes": cert_table_size,
                "note": "Er is een handtekeningblok aanwezig. Geldigheid/vertrouwensketen is NIET geverifieerd door deze tool — controleer handmatig met 'signtool verify' (Windows) of vergelijkbare tooling.",
            }
    except (struct.error, IndexError):
        return {"applicable": False, "note": "Kon Security Directory niet uitlezen (mogelijk afwijkend/corrupt formaat)."}


def per_section_entropy(data: bytes) -> list:
    """
    Berekent entropie PER PE-SECTION in plaats van over het hele bestand.
    Dit is forensisch waardevoller: een enkele hoog-entropie section
    tussen verder normale sections wijst specifiek op een ingebedde
    gepakte/versleutelde payload — een sterker signaal dan een totaal-cijfer.
    """
    import math
    from collections import Counter

    def entropy_of(chunk: bytes) -> float:
        if not chunk:
            return 0.0
        counts = Counter(chunk)
        length = len(chunk)
        e = 0.0
        for c in counts.values():
            p = c / length
            e -= p * math.log2(p)
        return round(e, 3)

    if len(data) < 64 or data[:2] != b"MZ":
        return []

    try:
        pe_offset = struct.unpack("<I", data[60:64])[0]
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return []

        num_sections = struct.unpack("<H", data[pe_offset + 6:pe_offset + 8])[0]
        magic_offset = pe_offset + 24
        magic = struct.unpack("<H", data[magic_offset:magic_offset + 2])[0]
        optional_header_size = 240 if magic == 0x20B else 224
        section_table_offset = pe_offset + 24 + optional_header_size

        results = []
        offset = section_table_offset
        for _ in range(min(num_sections, 20)):
            if offset + 40 > len(data):
                break
            name = data[offset:offset + 8].rstrip(b"\x00").decode(errors="ignore") or "(naamloos)"
            raw_size = struct.unpack("<I", data[offset + 16:offset + 20])[0]
            raw_ptr = struct.unpack("<I", data[offset + 20:offset + 24])[0]

            section_data = data[raw_ptr:raw_ptr + raw_size] if raw_ptr + raw_size <= len(data) else b""
            e = entropy_of(section_data)

            results.append({
                "name": name,
                "size_bytes": raw_size,
                "entropy": e,
                "flag": "hoog (mogelijk gepakt/versleuteld)" if e >= 7.2 else ("normaal" if raw_size > 0 else "leeg"),
            })
            offset += 40
        return results
    except (struct.error, IndexError):
        return []


def extract_strings(data: bytes, min_length: int = 6, max_results: int = 150) -> dict:
    """
    Extraheert leesbare ASCII- en UTF-16-strings uit binaire data — de
    standaard eerste stap in elke malware-analyse (vergelijkbaar met de
    Linux 'strings'-tool). Dit is vaak de bron van bruikbare IOC's:
    URL's, IP-adressen, bestandspaden, geregistreerde mutex-namen, etc.

    We groeperen de resultaten alvast op "interessantheid" zodat een
    analist niet honderden ruis-strings hoeft door te spitten.
    """
    ascii_strings = re.findall(rb"[\x20-\x7e]{%d,}" % min_length, data)
    utf16_strings = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length, data)
    decoded_utf16 = [s.decode("utf-16-le", errors="ignore") for s in utf16_strings]

    all_strings = [s.decode("ascii", errors="ignore") for s in ascii_strings] + decoded_utf16
    all_strings = list(dict.fromkeys(all_strings))  # dedupliceren, volgorde behouden

    iocs = {
        "urls": sorted(set(re.findall(r"https?://[^\s\"'<>]+", " ".join(all_strings)))),
        "ips": sorted(set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", " ".join(all_strings)))),
        "file_paths": sorted(set(re.findall(r"[A-Za-z]:\\[^\s\"'<>]+", " ".join(all_strings)))),
        "email_addresses": sorted(set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", " ".join(all_strings)))),
        "registry_keys": sorted(set(re.findall(r"(?:HKEY_[A-Z_]+|SOFTWARE)\\[^\s\"'<>]+", " ".join(all_strings)))),
    }

    return {
        "total_extracted": len(all_strings),
        "sample": all_strings[:max_results],
        "truncated": len(all_strings) > max_results,
        "indicators_of_compromise": iocs,
    }


def build_timeline(pe_timestamp: dict | None, evidence_received_at: str) -> list:
    """Zet alle bekende tijdstippen op één rij, gesorteerd."""
    events = [{"timestamp": evidence_received_at, "event": "Bewijsmateriaal ontvangen door analist"}]
    if pe_timestamp and pe_timestamp.get("parsed"):
        events.append({
            "timestamp": pe_timestamp["parsed"],
            "event": "PE compiler-timestamp (build-tijd volgens header)"
            + (" — VERDACHT/ONPLAUSIBEL" if pe_timestamp.get("suspicious") else ""),
        })
    events.sort(key=lambda e: e["timestamp"])
    return events


# ---------------------------------------------------------------------------
# PDF-EXPORT (via wkhtmltopdf, moet op het systeem geïnstalleerd zijn)
# ---------------------------------------------------------------------------

def render_html_to_pdf(html_content: str) -> bytes | None:
    """
    Rendert een HTML-string naar PDF-bytes via wkhtmltopdf (subprocess).
    Retourneert None als wkhtmltopdf niet beschikbaar is — de aanroeper
    moet dan een duidelijke foutmelding tonen (nooit stilzwijgend falen).
    """
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as html_file:
        html_file.write(html_content)
        html_path = html_file.name

    pdf_path = html_path.replace(".html", ".pdf")

    try:
        result = subprocess.run(
            [
                "wkhtmltopdf",
                "--enable-local-file-access",
                "--print-media-type",
                "--quiet",
                html_path,
                pdf_path,
            ],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        with open(pdf_path, "rb") as f:
            return f.read()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    finally:
        import os
        for p in (html_path, pdf_path):
            if os.path.exists(p):
                os.remove(p)
