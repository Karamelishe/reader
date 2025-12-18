const severityOrder = ["critical", "high", "medium", "low", "info"];
const severityNames = {
  critical: "Критичный",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  info: "Информационный",
};

const state = {
  issues: [],
  filtered: [],
  reportType: "—",
  severityFilters: new Set(severityOrder),
  lastFile: null,
};

const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("file-input");
const errorBox = document.getElementById("error");
const statusBox = document.getElementById("load-status");
const issuesContainer = document.getElementById("issues");
const severityFilterContainer = document.getElementById("severity-filters");
const searchInput = document.getElementById("search");
const severityBar = document.getElementById("severity-bar");

const semgrepSampleBtn = document.getElementById("load-semgrep-sample");
const sarifSampleBtn = document.getElementById("load-sarif-sample");
const uploadServerBtn = document.getElementById("upload-server-btn");
const downloadPdfBtn = document.getElementById("download-pdf");
const shareStatus = document.getElementById("share-status");
const shareLink = document.getElementById("share-link");
const tabs = document.querySelectorAll(".tab");
const tabContents = document.querySelectorAll(".tab-content");
const historyList = document.getElementById("history-list");
const refreshHistoryBtn = document.getElementById("refresh-history");

function setStatus(message) {
  statusBox.textContent = message || "";
}

function setError(message) {
  errorBox.textContent = message || "";
}

function setShareStatus(message, link) {
  shareStatus.textContent = message || "";
  if (link) {
    shareLink.textContent = link;
    shareLink.href = link;
    shareLink.style.display = "block";
  } else {
    shareLink.textContent = "";
    shareLink.removeAttribute("href");
    shareLink.style.display = "none";
  }
}

function switchTab(target) {
  tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === target));
  tabContents.forEach((panel) => panel.classList.toggle("active", panel.dataset.tab === target));
}

function normalizeSeverity(raw = "info") {
  const value = String(raw).toLowerCase();
  if (value.includes("critical")) return "critical";
  if (value.includes("high")) return "high";
  if (value.includes("error") || value.includes("err")) return "high";
  if (value.includes("warn")) return "medium";
  if (value.includes("medium")) return "medium";
  if (value.includes("low")) return "low";
  if (value.includes("note")) return "info";
  return "info";
}

function isSarif(data) {
  return Boolean(data && Array.isArray(data.runs));
}

function isSemgrep(data) {
  return Boolean(data && Array.isArray(data.results));
}

function parseSarif(data) {
  const issues = [];

  data.runs.forEach((run, runIndex) => {
    const rules = new Map();
    (run.tool?.driver?.rules || []).forEach((rule) => {
      rules.set(rule.id, rule);
    });

    (run.results || []).forEach((result, resultIndex) => {
      const location = result.locations?.[0]?.physicalLocation;
      const region = location?.region || {};
      const rule = rules.get(result.ruleId) || {};

      issues.push({
        id: `sarif-${runIndex}-${resultIndex}`,
        severity: normalizeSeverity(
          result.level ||
            result.properties?.["problem.severity"] ||
            result.partialFingerprints?.["severity/semgrep"] ||
            "info"
        ),
        message: result.message?.text || "Описание отсутствует",
        ruleId: result.ruleId || rule.name || "rule",
        path: location?.artifactLocation?.uri || "—",
        startLine: region.startLine,
        endLine: region.endLine,
        snippet: region.snippet?.text || "",
        tags: rule.properties?.tags || [],
        references: rule.helpUri ? [rule.helpUri] : [],
        source: "SARIF",
        tool: run.tool?.driver?.name || "",
        fingerprint: Object.values(result.partialFingerprints || {}).join(", "),
      });
    });
  });

  return { issues, type: "SARIF" };
}

function parseSemgrep(data) {
  const issues = (data.results || []).map((result, index) => {
    const tags = [];
    const metadata = result.extra?.metadata || {};
    if (Array.isArray(metadata.cwe)) tags.push(...metadata.cwe);
    if (Array.isArray(metadata.owasp)) tags.push(...metadata.owasp);
    if (metadata.category) tags.push(metadata.category);

    return {
      id: `semgrep-${index}`,
      severity: normalizeSeverity(result.extra?.severity || "info"),
      message: result.extra?.message || "Описание отсутствует",
      ruleId: result.check_id || "rule",
      path: result.path || "—",
      startLine: result.start?.line,
      endLine: result.end?.line,
      snippet: result.extra?.lines || "",
      tags,
      references: metadata.references || [],
      source: "Semgrep JSON",
      tool: "Semgrep",
      fingerprint: result.extra?.fingerprint || "",
    };
  });

  return { issues, type: "Semgrep JSON" };
}

function normalizeReport(data) {
  if (isSarif(data)) return parseSarif(data);
  if (isSemgrep(data)) return parseSemgrep(data);
  throw new Error("Не удалось определить формат файла. Ожидается SARIF или Semgrep JSON.");
}

function handleFile(file) {
  if (!file) return;
  setError("");
  setStatus(`Загружаем ${file.name}...`);
  state.lastFile = file;
  uploadServerBtn.disabled = false;
  downloadPdfBtn.disabled = false;
  setShareStatus("", "");

  const reader = new FileReader();
  reader.onload = (event) => {
    try {
      const json = JSON.parse(event.target.result);
      const parsed = normalizeReport(json);
      state.issues = parsed.issues;
      state.reportType = parsed.type;
      applyFilters();
      setStatus(`Загружено: ${file.name}`);
    } catch (err) {
      console.error(err);
      setError(err.message);
      setStatus("");
      state.lastFile = null;
      uploadServerBtn.disabled = true;
      downloadPdfBtn.disabled = true;
      setShareStatus("", "");
      state.issues = [];
      state.filtered = [];
      renderIssues();
      renderSummary();
    }
  };

  reader.onerror = () => {
    setError("Не удалось прочитать файл");
    setStatus("");
  };

  reader.readAsText(file);
}

async function uploadToServer() {
  if (!state.lastFile) {
    setShareStatus("Сначала загрузите отчёт локально");
    return;
  }

  try {
    setShareStatus("Отправляем файл на сервер...");
    const body = new FormData();
    body.append("report", state.lastFile, state.lastFile.name);

    const response = await fetch("/upload", { method: "POST", body });
    const data = await response.json();

    if (!response.ok) throw new Error(data.error || "Не удалось загрузить файл");

    const shareUrl = data.url;
    const linkWithParam = `${window.location.origin}${window.location.pathname}?report=${encodeURIComponent(
      shareUrl
    )}`;
    setShareStatus("Ссылка готова. Отправьте разработчикам:", linkWithParam);
    await loadHistory();
  } catch (err) {
    setShareStatus(err.message || "Ошибка при загрузке");
  }
}

async function loadHistory() {
  try {
    const response = await fetch("/reports");
    if (!response.ok) throw new Error("Не удалось получить список отчётов");
    const data = await response.json();
    renderHistory(data.files || []);
  } catch (err) {
    historyList.innerHTML = `<p class="error">${err.message}</p>`;
  }
}

function downloadPdf() {
  if (!state.filtered.length) {
    alert("Сначала загрузите отчёт");
    return;
  }
  document.body.classList.add("print-mode");
  const cleanup = () => {
    document.body.classList.remove("print-mode");
    window.removeEventListener("afterprint", cleanup);
  };

  window.addEventListener("afterprint", cleanup);
  setTimeout(() => window.print(), 0);
}

function renderHistory(files) {
  historyList.innerHTML = "";
  if (!files.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "Загруженных отчётов пока нет";
    historyList.appendChild(empty);
    return;
  }

  files.forEach((file) => {
    const item = document.createElement("div");
    item.className = "history-item";

    const info = document.createElement("div");
    const name = document.createElement("div");
    name.textContent = file.name;
    const date = document.createElement("p");
    date.className = "muted";
    const dt = new Date(file.created * 1000);
    date.textContent = dt.toLocaleString();
    info.append(name, date);

    const openBtn = document.createElement("button");
    openBtn.className = "button ghost";
    openBtn.textContent = "Открыть";
    openBtn.addEventListener("click", () => {
      const link = `${window.location.origin}${window.location.pathname}?report=${encodeURIComponent(
        file.url
      )}`;
      window.location.href = link;
    });

    const deleteBtn = document.createElement("button");
    deleteBtn.className = "button";
    deleteBtn.textContent = "Удалить";
    deleteBtn.addEventListener("click", async () => {
      if (!confirm("Удалить отчёт?")) return;
      const response = await fetch(file.url, { method: "DELETE" });
      if (!response.ok) {
        alert("Не удалось удалить отчёт");
        return;
      }
      await loadHistory();
    });

    item.append(info, openBtn, deleteBtn);
    historyList.appendChild(item);
  });
}

function buildSeverityFilters() {
  severityFilterContainer.innerHTML = "";

  severityOrder.forEach((level) => {
    const chip = document.createElement("button");
    chip.className = `chip active severity-${level}`;
    chip.dataset.level = level;
    chip.innerHTML = `<span class="dot" style="background: var(--${level})"></span>${
      severityNames[level]
    }`;
    chip.addEventListener("click", () => toggleSeverity(level, chip));
    severityFilterContainer.appendChild(chip);
  });
}

function toggleSeverity(level, chip) {
  if (state.severityFilters.has(level) && state.severityFilters.size === 1) {
    return; // минимум один уровень
  }
  if (state.severityFilters.has(level)) {
    state.severityFilters.delete(level);
    chip.classList.remove("active");
  } else {
    state.severityFilters.add(level);
    chip.classList.add("active");
  }
  applyFilters();
}

function applyFilters() {
  const query = searchInput.value.trim().toLowerCase();

  state.filtered = state.issues.filter((issue) => {
    const matchesSeverity = state.severityFilters.has(issue.severity);
    const matchesQuery = !query
      ? true
      : [
          issue.message,
          issue.ruleId,
          issue.path,
          issue.tags?.join(" "),
          issue.fingerprint,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase()
          .includes(query);

    return matchesSeverity && matchesQuery;
  });

  state.filtered.sort((a, b) => {
    const severityDiff =
      severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
    if (severityDiff !== 0) return severityDiff;

    const pathDiff = (a.path || "").localeCompare(b.path || "");
    if (pathDiff !== 0) return pathDiff;

    return (a.startLine || 0) - (b.startLine || 0);
  });

  renderSummary();
  renderSeverityBar();
  renderIssues();
}

function renderSummary() {
  const total = state.filtered.length;
  const files = new Set(state.filtered.map((i) => i.path)).size;
  const rules = new Set(state.filtered.map((i) => i.ruleId)).size;

  document.getElementById("total-findings").textContent = total || "—";
  document.getElementById("total-files").textContent = files || "—";
  document.getElementById("total-rules").textContent = rules || "—";
  document.getElementById("report-type").textContent = state.reportType || "—";
}

function renderSeverityBar() {
  const counts = severityOrder.reduce((acc, level) => ({ ...acc, [level]: 0 }), {});
  state.filtered.forEach((issue) => {
    counts[issue.severity] = (counts[issue.severity] || 0) + 1;
  });

  const max = Math.max(...Object.values(counts), 1);
  severityBar.innerHTML = "";

  severityOrder.forEach((level) => {
    const slice = document.createElement("div");
    slice.className = "slice";

    const bar = document.createElement("span");
    bar.style.width = `${(counts[level] / max) * 100}%`;
    bar.style.background = `var(--${level})`;
    slice.appendChild(bar);

    const label = document.createElement("div");
    label.className = "label";
    label.textContent = `${severityNames[level]} · ${counts[level]}`;
    slice.appendChild(label);

    severityBar.appendChild(slice);
  });
}

function renderIssues() {
  issuesContainer.innerHTML = "";

  if (!state.filtered.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = state.issues.length
      ? "Ничего не найдено с такими фильтрами"
      : "Загрузите отчёт, чтобы увидеть результаты";
    issuesContainer.appendChild(empty);
    return;
  }

  state.filtered.forEach((issue) => {
    const card = document.createElement("article");
    card.className = "issue-card";

    const header = document.createElement("div");
    header.className = "issue-header";

    const severity = document.createElement("span");
    severity.className = "severity-pill";
    severity.style.background = `var(--${issue.severity})`;
    severity.textContent = severityNames[issue.severity] || issue.severity;

    const rule = document.createElement("span");
    rule.className = "rule-id";
    rule.textContent = issue.ruleId;

    const path = document.createElement("span");
    path.className = "path";
    path.textContent = `${issue.path}:${issue.startLine || "?"}`;

    header.append(severity, rule, path);

    const message = document.createElement("p");
    message.className = "message";
    message.textContent = issue.message;

    const meta = document.createElement("div");
    meta.className = "meta";
    if (issue.source) meta.append(childMeta(`Источник: ${issue.source}`));
    if (issue.tool) meta.append(childMeta(`Инструмент: ${issue.tool}`));
    if (issue.fingerprint) meta.append(childMeta(`Fingerprint: ${issue.fingerprint}`));
    if (issue.tags?.length) meta.append(childMeta(`Тэги: ${issue.tags.join(", ")}`));
    if (issue.references?.length)
      meta.append(childMeta(`Справка: ${issue.references.join(", ")}`));

    const snippet = document.createElement("pre");
    snippet.className = "snippet";
    snippet.textContent = issue.snippet || "Фрагмент кода не предоставлен";

    card.append(header, message, meta, snippet);
    issuesContainer.appendChild(card);
  });
}

function childMeta(text) {
  const span = document.createElement("span");
  span.textContent = text;
  return span;
}

function setupDropZone() {
  const activeClass = () => dropZone.classList.add("dragging");
  const inactiveClass = () => dropZone.classList.remove("dragging");

  ["dragenter", "dragover"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      activeClass();
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      inactiveClass();
    });
  });

  dropZone.addEventListener("drop", (event) => {
    const file = event.dataTransfer?.files?.[0];
    handleFile(file);
  });
}

function setupFileInput() {
  fileInput.addEventListener("change", (event) => {
    const file = event.target.files?.[0];
    handleFile(file);
  });
}

function setupSearch() {
  searchInput.addEventListener("input", () => applyFilters());
}

async function loadSample(path) {
  try {
    setError("");
    setStatus("Загружаем пример...");
    const response = await fetch(path);
    if (!response.ok) throw new Error("Не удалось загрузить пример");
    const json = await response.json();
    const parsed = normalizeReport(json);
    state.issues = parsed.issues;
    state.reportType = parsed.type + " (sample)";
    state.lastFile = null;
    uploadServerBtn.disabled = true;
    downloadPdfBtn.disabled = false;
    setShareStatus("", "");
    applyFilters();
    setStatus("Пример загружен");
  } catch (err) {
    setError(err.message);
    setStatus("");
  }
}

async function loadRemoteReport(url) {
  try {
    setError("");
    setStatus("Загружаем отчёт по ссылке...");
    const response = await fetch(url);
    if (!response.ok) throw new Error("Не удалось загрузить удалённый отчёт");
    const json = await response.json();
    const parsed = normalizeReport(json);
    state.issues = parsed.issues;
    state.reportType = parsed.type + " (remote)";
    state.lastFile = null;
    uploadServerBtn.disabled = true;
    downloadPdfBtn.disabled = false;
    setShareStatus("", "");
    applyFilters();
    setStatus("Отчёт загружен по ссылке");
  } catch (err) {
    setError(err.message);
    setStatus("");
  }
}

function init() {
  buildSeverityFilters();
  setupDropZone();
  setupFileInput();
  setupSearch();
  uploadServerBtn.addEventListener("click", uploadToServer);
  downloadPdfBtn.addEventListener("click", downloadPdf);
  tabs.forEach((tab) =>
    tab.addEventListener("click", () => {
      switchTab(tab.dataset.tab);
      if (tab.dataset.tab === "history") {
        loadHistory();
      }
    })
  );
  refreshHistoryBtn.addEventListener("click", loadHistory);
  setShareStatus("", "");
  renderSummary();
  renderSeverityBar();
  renderIssues();

  semgrepSampleBtn.addEventListener("click", () => loadSample("samples/semgrep-sample.json"));
  sarifSampleBtn.addEventListener("click", () => loadSample("samples/semgrep-sample.sarif"));

  const reportParam = new URLSearchParams(window.location.search).get("report");
  if (reportParam) {
    loadRemoteReport(reportParam);
  }
}

init();
