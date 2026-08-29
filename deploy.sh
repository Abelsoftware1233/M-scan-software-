#!/usr/bin/env bash
#
# deploy.sh — MalScan deployment script
# =======================================
# Zet MalScan op als systemd-service, draaiend in een eigen venv onder
# gunicorn. Nginx (reverse proxy, TLS) wordt bewust NIET door dit script
# geconfigureerd — dat regel je zelf.
#
# Gebruik:
#   sudo ./deploy.sh
#
# Vereisten: Ubuntu/Debian-achtig systeem met systemd, Python 3.10+.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuratie — pas aan naar wens
# ---------------------------------------------------------------------------
APP_NAME="malscan"
APP_USER="malscan"                       # dedicated, unprivileged systeemgebruiker
APP_DIR="/opt/malscan"                   # waar de code komt te staan
VENV_DIR="${APP_DIR}/venv"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
BIND_HOST="127.0.0.1"                    # alleen lokaal; Nginx doet de externe kant
BIND_PORT="5777"
GUNICORN_WORKERS="3"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"  # map waar dit script staat

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo -e "\033[1;32m[deploy]\033[0m $*"; }
warn() { echo -e "\033[1;33m[deploy]\033[0m $*"; }
die()  { echo -e "\033[1;31m[deploy]\033[0m $*" >&2; exit 1; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "Dit script moet als root draaien (gebruik: sudo ./deploy.sh)"
    fi
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Commando '$1' niet gevonden. Installeer het eerst."
}

# ---------------------------------------------------------------------------
# 0. Voorwaarden checken
# ---------------------------------------------------------------------------
require_root
require_command python3
require_command systemctl

if ! command -v wkhtmltopdf >/dev/null 2>&1; then
    warn "wkhtmltopdf niet gevonden — PDF-export in MalScan zal niet werken."
    warn "Installeer met: apt install wkhtmltopdf"
fi

PYTHON_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
log "Python versie gevonden: ${PYTHON_VERSION}"

if [[ ! -f "${SOURCE_DIR}/app.py" ]]; then
    die "app.py niet gevonden in ${SOURCE_DIR}. Draai dit script vanuit de malscan-backend map."
fi

# ---------------------------------------------------------------------------
# 1. Dedicated systeemgebruiker aanmaken (geen login, geen shell)
# ---------------------------------------------------------------------------
if id "${APP_USER}" &>/dev/null; then
    log "Gebruiker '${APP_USER}' bestaat al, sla aanmaken over."
else
    log "Systeemgebruiker '${APP_USER}' aanmaken (geen shell/login)..."
    useradd --system --no-create-home --shell /usr/sbin/nologin "${APP_USER}"
fi

# ---------------------------------------------------------------------------
# 2. Applicatiecode naar APP_DIR kopiëren
# ---------------------------------------------------------------------------
log "Code kopiëren naar ${APP_DIR}..."
mkdir -p "${APP_DIR}"

# rsync als beschikbaar (respecteert .gitignore-achtige excludes beter),
# anders terugvallen op cp.
if command -v rsync >/dev/null 2>&1; then
    rsync -a --exclude 'venv' --exclude '__pycache__' --exclude '.git' \
        "${SOURCE_DIR}/" "${APP_DIR}/"
else
    cp -r "${SOURCE_DIR}/." "${APP_DIR}/"
    rm -rf "${APP_DIR}/venv" "${APP_DIR}/__pycache__"
fi

# ---------------------------------------------------------------------------
# 3. Virtual environment aanmaken + dependencies installeren
# ---------------------------------------------------------------------------
if [[ -d "${VENV_DIR}" ]]; then
    log "Venv bestaat al onder ${VENV_DIR}, hergebruiken."
else
    log "Virtual environment aanmaken onder ${VENV_DIR}..."
    python3 -m venv "${VENV_DIR}"
fi

log "Dependencies installeren in venv..."
"${VENV_DIR}/bin/pip" install --upgrade pip --quiet
"${VENV_DIR}/bin/pip" install -r "${APP_DIR}/requirements.txt" --quiet
"${VENV_DIR}/bin/pip" install gunicorn --quiet

# ---------------------------------------------------------------------------
# 4. Eigendom en permissies zetten
# ---------------------------------------------------------------------------
log "Eigendom instellen op ${APP_USER}..."
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"
chmod -R go-w "${APP_DIR}"

# ---------------------------------------------------------------------------
# 5. systemd unit-bestand schrijven
# ---------------------------------------------------------------------------
log "systemd-service schrijven naar ${SERVICE_FILE}..."
cat > "${SERVICE_FILE}" << UNIT
[Unit]
Description=MalScan — heuristische malware-scanner & forensisch rapportagetool
After=network.target
Documentation=file://${APP_DIR}/README.md

[Service]
Type=simple
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${APP_DIR}
Environment="PATH=${VENV_DIR}/bin"
ExecStart=${VENV_DIR}/bin/gunicorn \\
    --workers ${GUNICORN_WORKERS} \\
    --bind ${BIND_HOST}:${BIND_PORT} \\
    --timeout 60 \\
    --access-logfile - \\
    --error-logfile - \\
    app:app

Restart=on-failure
RestartSec=5

# --- Hardening ---
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${APP_DIR}
# Scans verwerken bestanden alleen in-memory (geen writes buiten ReadWritePaths nodig).

[Install]
WantedBy=multi-user.target
UNIT

# ---------------------------------------------------------------------------
# 6. Service inladen, inschakelen en starten
# ---------------------------------------------------------------------------
log "systemd herladen en service inschakelen..."
systemctl daemon-reload
systemctl enable "${APP_NAME}"
systemctl restart "${APP_NAME}"

sleep 2

# ---------------------------------------------------------------------------
# 7. Statuscheck
# ---------------------------------------------------------------------------
if systemctl is-active --quiet "${APP_NAME}"; then
    log "MalScan draait als service '${APP_NAME}' op ${BIND_HOST}:${BIND_PORT}"
else
    warn "Service lijkt niet actief. Bekijk de logs met:"
    warn "  journalctl -u ${APP_NAME} -n 50 --no-pager"
    exit 1
fi

if command -v curl >/dev/null 2>&1; then
    log "Health-check uitvoeren..."
    if curl -fsS "http://${BIND_HOST}:${BIND_PORT}/api/health" >/dev/null 2>&1; then
        log "Health-check geslaagd — backend reageert correct."
    else
        warn "Health-check gaf geen 200 terug. Controleer 'journalctl -u ${APP_NAME}'."
    fi
fi

# ---------------------------------------------------------------------------
# 8. Vervolgstappen (Nginx bewust NIET meegenomen)
# ---------------------------------------------------------------------------
cat << NEXTSTEPS

────────────────────────────────────────────────────────────────
MalScan is gedeployed.

  Service naam:   ${APP_NAME}
  Luistert op:    ${BIND_HOST}:${BIND_PORT}  (alleen lokaal bereikbaar)
  App-map:        ${APP_DIR}
  Draait als:     ${APP_USER}

Nuttige commando's:
  systemctl status ${APP_NAME}        # status bekijken
  systemctl restart ${APP_NAME}       # herstarten na code-update
  journalctl -u ${APP_NAME} -f        # live logs volgen

Nginx (reverse proxy + TLS) configureer je zelf. De backend luistert
alleen op 127.0.0.1:${BIND_PORT} — richt je Nginx 'proxy_pass' daarop, bijv.:

  proxy_pass http://127.0.0.1:${BIND_PORT};

Vergeet niet 'client_max_body_size' in Nginx te verhogen als je grotere
bestanden dan de standaard 1MB wilt kunnen uploaden/scannen.
────────────────────────────────────────────────────────────────
NEXTSTEPS
