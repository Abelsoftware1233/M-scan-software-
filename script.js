// MalScan frontend — praat met de lokale Flask-backend op dezelfde host/poort (5777)
const API_BASE = ""; // leeg = zelfde origin (Flask serveert dit bestand zelf)

const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
const errorBox = document.getElementById("error-box");
const backendStatus = document.getElementById("backend-status");
const statusDot = document.querySelector(".dot");

const gaugeEmpty = document.getElementById("gauge-empty");
const gaugeResult = document.getElementById("gauge-result");
const gaugeFill = document.getElementById("gauge-fill");
const gaugeScore = document.getElementById("gauge-score");
const verdictBadge = document.getElementById("verdict-badge");

const resultEmpty = document.getElementById("result-empty");
const resultContent = document.getElementById("result-content");
const statFilename = document.getElementById("stat-filename");
const statSize = document.getElementById("stat-size");
const statEntropy = document.getElementById("stat-entropy");
const statPatterns = document.getElementById("stat-patterns");
const statHash = document.getElementById("stat-hash");
const reasonsList = document.getElementById("reasons-list");

const classificationEmpty = document.getElementById("classification-empty");
const classificationContent = document.getElementById("classification-content");
const classificationList = document.getElementById("classification-list");
const officeBadge = document.getElementById("office-badge");
const packingNote = document.getElementById("packing-note");

const historyEmpty = document.getElementById("history-empty");
const historyList = document.getElementById("history-list");

const logOutput = document.getElementById("log-output");

const analystInput = document.getElementById("analyst-input");
const caseIdInput = document.getElementById("caseid-input");
const forensicBtn = document.getElementById("forensic-btn");
const forensicResult = document.getElementById("forensic-result");
const forensicCaseId = document.getElementById("forensic-case-id");
const forensicViewHtml = document.getElementById("forensic-view-html");
const forensicDownloadPdf = document.getElementById("forensic-download-pdf");

let currentFile = null; // laatst gescande File-object, nodig voor het forensisch rapport

const VERDICT_STYLES = {
  malicious: { color: "#FF5C5C", bg: "rgba(255,92,92,0.12)", label: "⛔ MALICIOUS" },
  suspicious: { color: "#FFB84D", bg: "rgba(255,184,77,0.12)", label: "⚠ SUSPICIOUS" },
  clean: { color: "#3DDC97", bg: "rgba(61,220,151,0.12)", label: "✓ CLEAN" },
};

const CIRCUMFERENCE = 2 * Math.PI * 54;
let history = [];
let logCleared = false;

function addLog(text, level = "info") {
  if (!logCleared) { logOutput.innerHTML = ""; logCleared = true; }
  const colors = { info: "#5B8DEF", warn: "#FFB84D", error: "#FF5C5C", ok: "#3DDC97" };
  const line = document.createElement("div");
  line.className = "log-line";
  const time = new Date().toLocaleTimeString("nl-NL", { hour12: false });
  line.innerHTML = `<span class="log-time">${time}</span><span class="log-arrow" style="color:${colors[level]}">›</span><span class="log-text">${escapeHtml(text)}</span>`;
  logOutput.appendChild(line);
  logOutput.scrollTop = logOutput.scrollHeight;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function showError(msg) {
  errorBox.textContent = msg;
  errorBox.classList.remove("hidden");
}

function clearError() {
  errorBox.classList.add("hidden");
  errorBox.textContent = "";
}

async function checkBackend() {
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    if (res.ok) {
      backendStatus.textContent = "backend online · poort 5777";
      statusDot.classList.remove("offline");
    } else {
      throw new Error("unhealthy");
    }
  } catch {
    backendStatus.textContent = "backend niet bereikbaar";
    statusDot.classList.add("offline");
  }
}

async function scanFile(file) {
  clearError();
  logCleared = false;
  currentFile = file;
  forensicBtn.disabled = false;
  forensicResult.classList.add("hidden");
  addLog(`Bestand geselecteerd: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`, "info");
  addLog("Versturen naar backend (POST /api/scan)...", "info");

  const formData = new FormData();
  formData.append("file", file);

  try {
    const res = await fetch(`${API_BASE}/api/scan`, { method: "POST", body: formData });
    const data = await res.json();

    if (!res.ok) {
      addLog(`Fout: ${data.error || "onbekende fout"}`, "error");
      showError(data.error || "Scan mislukt");
      return;
    }

    addLog(`SHA-256: ${data.hashes.sha256.slice(0, 32)}...`, "info");
    if (data.known_hash_match) {
      addLog(`⚠ Hash match: ${data.known_hash_match.name}`, "error");
    } else {
      addLog("Geen match in hash-database", "ok");
    }

    addLog(`Entropie: ${data.entropy} / 8`, data.entropy >= 7.0 ? "warn" : "ok");

    if (data.pattern_findings.length > 0) {
      data.pattern_findings.forEach((f) =>
        addLog(`⚠ Patroon '${f.rule}' (${f.category}) — ${f.match_count}x`, "warn")
      );
    } else {
      addLog("Geen verdachte patronen gevonden", "ok");
    }

    if (data.pe_info && data.pe_info.suspicious_sections && data.pe_info.suspicious_sections.length > 0) {
      addLog(`⚠ Verdachte PE-sections: ${data.pe_info.suspicious_sections.join(", ")}`, "warn");
    }

    if (data.classification.office_document) {
      addLog(`📄 Office-document herkend: ${data.classification.office_document.format}`, "info");
    }
    if (data.classification.classifications.length > 0) {
      data.classification.classifications.forEach((c) =>
        addLog(`🏷 Classificatie: ${c.type}`, "warn")
      );
    }

    addLog(
      `Scan voltooid — verdict: ${data.risk.verdict.toUpperCase()} (score ${data.risk.score}/100)`,
      data.risk.verdict === "clean" ? "ok" : "error"
    );

    renderResult(data);
    pushHistory(data);
  } catch (e) {
    addLog(`Netwerkfout: ${e.message}`, "error");
    showError(
      "Kon geen verbinding maken met de backend op poort 5777. Draai je 'python app.py'? " +
      "Controleer of de server actief is op http://localhost:5777."
    );
  }
}

function renderResult(data) {
  // Gauge
  gaugeEmpty.classList.add("hidden");
  gaugeResult.classList.remove("hidden");
  const style = VERDICT_STYLES[data.risk.verdict];
  const offset = CIRCUMFERENCE - (data.risk.score / 100) * CIRCUMFERENCE;
  gaugeFill.style.strokeDashoffset = offset;
  gaugeFill.style.stroke = style.color;
  gaugeScore.textContent = data.risk.score;
  gaugeScore.style.color = style.color;
  verdictBadge.textContent = style.label;
  verdictBadge.style.background = style.bg;
  verdictBadge.style.color = style.color;

  renderClassification(data.classification);

  // Resultaatpaneel
  resultEmpty.classList.add("hidden");
  resultContent.classList.remove("hidden");
  statFilename.textContent = data.filename;
  statFilename.title = data.filename;
  statSize.textContent = `${(data.size_bytes / 1024).toFixed(1)} KB`;
  statEntropy.textContent = `${data.entropy} / 8`;
  statPatterns.textContent = `${data.pattern_findings.length} gevonden`;
  statHash.textContent = data.hashes.sha256;
  statHash.title = data.hashes.sha256;

  reasonsList.innerHTML = "";
  if (data.risk.reasons.length > 0) {
    data.risk.reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      reasonsList.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.style.setProperty("--no-bullet", "1");
    li.textContent = "Geen verdachte kenmerken aangetroffen door de huidige regelset.";
    reasonsList.appendChild(li);
  }
}

function renderClassification(classification) {
  classificationEmpty.classList.add("hidden");
  classificationContent.classList.remove("hidden");

  // Office-document badge
  if (classification.office_document) {
    officeBadge.classList.remove("hidden");
    officeBadge.innerHTML = `<span class="icon">📄</span> ${escapeHtml(classification.office_document.format)}`;
  } else {
    officeBadge.classList.add("hidden");
  }

  // Classificatie-lijst
  classificationList.innerHTML = "";
  if (classification.classifications.length === 0) {
    const div = document.createElement("div");
    div.className = "no-classification";
    div.innerHTML = `✓ Geen specifiek malware-type herkend op basis van de huidige regelset.`;
    classificationList.appendChild(div);
  } else {
    classification.classifications.forEach((c, i) => {
      const div = document.createElement("div");
      div.className = `classification-item ${i === 0 ? "primary" : "secondary"}`;
      const tags = c.matched_categories.map((cat) => `<span class="classification-tag">${escapeHtml(cat)}</span>`).join("");
      div.innerHTML = `
        <div class="classification-item-title">${i === 0 ? "🎯" : "▫"} ${escapeHtml(c.type)}</div>
        <div class="classification-item-desc">${escapeHtml(c.description)}</div>
        <div class="classification-item-tags">${tags}</div>
      `;
      classificationList.appendChild(div);
    });
  }

  // Packing note
  if (classification.packing_note) {
    packingNote.classList.remove("hidden");
    packingNote.textContent = classification.packing_note;
  } else {
    packingNote.classList.add("hidden");
  }
}

function pushHistory(data) {
  history.unshift(data);
  history = history.slice(0, 10);
  historyEmpty.classList.add("hidden");
  historyList.innerHTML = "";
  history.forEach((h) => {
    const style = VERDICT_STYLES[h.risk.verdict];
    const row = document.createElement("div");
    row.className = "history-item";
    row.innerHTML = `<span class="fname" title="${escapeHtml(h.filename)}">${escapeHtml(h.filename)}</span><span style="color:${style.color}">${h.risk.score}</span>`;
    historyList.appendChild(row);
  });
}

// Event listeners
dropzone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", (e) => {
  const file = e.target.files?.[0];
  if (file) scanFile(file);
});
dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("dragover");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
  const file = e.dataTransfer.files?.[0];
  if (file) scanFile(file);
});

async function generateForensicReport() {
  if (!currentFile) return;

  forensicBtn.disabled = true;
  forensicBtn.textContent = "Rapport genereren...";
  clearError();
  addLog("Forensisch rapport genereren (POST /api/forensic-scan)...", "info");

  const formData = new FormData();
  formData.append("file", currentFile);
  if (analystInput.value.trim()) formData.append("analyst", analystInput.value.trim());
  if (caseIdInput.value.trim()) formData.append("case_id", caseIdInput.value.trim());

  try {
    const res = await fetch(`${API_BASE}/api/forensic-scan`, { method: "POST", body: formData });
    const data = await res.json();

    if (!res.ok) {
      addLog(`Fout bij rapportgeneratie: ${data.error || "onbekend"}`, "error");
      showError(data.error || "Forensisch rapport genereren mislukt");
      return;
    }

    addLog(`Forensisch rapport gegenereerd — case-ID: ${data.case_id}`, "ok");

    forensicResult.classList.remove("hidden");
    forensicCaseId.textContent = data.case_id;

    const htmlBlob = new Blob([data.html_report], { type: "text/html" });
    const htmlUrl = URL.createObjectURL(htmlBlob);
    forensicViewHtml.href = htmlUrl;

    forensicDownloadPdf.href = `${API_BASE}${data.pdf_url}`;
  } catch (e) {
    addLog(`Netwerkfout bij rapportgeneratie: ${e.message}`, "error");
    showError("Kon geen verbinding maken met de backend voor het forensisch rapport.");
  } finally {
    forensicBtn.disabled = false;
    forensicBtn.textContent = "Genereer incident-rapport";
  }
}

forensicBtn.addEventListener("click", generateForensicReport);

checkBackend();
setInterval(checkBackend, 15000);
