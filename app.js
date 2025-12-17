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

function setStatus(message) {
  statusBox.textContent = message || "";
}

function setError(message) {
  errorBox.textContent = message || "";
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
    applyFilters();
    setStatus("Пример загружен");
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
  renderSummary();
  renderSeverityBar();
  renderIssues();

  semgrepSampleBtn.addEventListener("click", () => loadSample("samples/semgrep-sample.json"));
  sarifSampleBtn.addEventListener("click", () => loadSample("samples/semgrep-sample.sarif"));
}

init();
