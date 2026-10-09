"use strict";

/* Front end for the log tools. The browser is only the window: every file
   access and every replacement happens in the local Python process. */

const TOKEN = new URLSearchParams(location.search).get("t") || "";
history.replaceState(null, "", location.pathname);

const $ = (id) => document.getElementById(id);
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

async function apiOnce(route, body) {
  const response = await fetch(route, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-LogMasque-Token": TOKEN },
    body: JSON.stringify(body || {}),
  });
  const payload = await response.json();
  if (!payload.ok) throw Object.assign(new Error(payload.error || "Unbekannter Fehler"), payload);
  return payload.data;
}

// A request that never reaches the local service throws a bare "Failed to fetch"
// without ever being logged server side. Repeating it costs little and gets past
// a dropped connection; a refusal from the service itself is passed on at once.
async function api(route, body, attempts = 3) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await apiOnce(route, body);
    } catch (error) {
      if (error.ok === false || error.error) throw error;
      lastError = error;
      if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, 150 * attempt));
    }
  }
  throw lastError;
}

const CATEGORY_LABELS = {
  IPv4: "IPv4-Adresse",
  IPv6: "IPv6-Adresse",
  Mail: "E-Mail-Adresse",
  Domain: "Domain",
  Ptr: "PTR-Eintrag",
  Extra: "Eigener Begriff",
  Person: "Name",
  Company: "Firma",
  Phone: "Telefon",
  Street: "Straße",
  City: "PLZ und Ort",
  Register: "Register",
  Account: "IBAN",
  Restored: "Zurückgewandelt",
};

// Short marker so a replacement stays identifiable without relying on color.
const CATEGORY_TAGS = {
  IPv4: "4", IPv6: "6", Mail: "@", Domain: "D", Ptr: "P", Extra: "*",
  Person: "N", Company: "F", Phone: "T", Street: "S", City: "O", Register: "R", Account: "K", Restored: "↺",
};
const CATEGORY_COLORS = {
  IPv4: "blue", IPv6: "purple", Mail: "green", Domain: "orange", Ptr: "teal", Extra: "pink",
  Person: "indigo", Company: "brown", Phone: "red", Street: "cyan", City: "cyan", Register: "olive", Account: "olive",
};
// Store categories as the store card shows them.
const STORE_LABELS = {
  IPv4: "IPv4", IPv6: "IPv6", Domain: "Domains", Local: "Postfächer", Host: "Hosts", Extra: "Begriffe",
  Person: "Namen", Company: "Firmen", Phone: "Telefon", Street: "Straßen", City: "Orte", Register: "Register",
  Account: "Konten",
};

const state = {
  info: null,
  collect: { sources: [], matrix: null, selection: new Set(), mode: "folder", job: null },
  anon: { mode: "text", files: [], job: null, lastResult: "" },
  lists: { terms: [], patterns: [], ignored: [], available: false },
};

// Errors the interface shows are repeated into the tool's log file. A failed
// request cannot report itself, so the attempt is retried once shortly after.
async function reportToLog(level, message, context) {
  const send = () => api("/api/clientlog", { level, message: String(message), context: context || "" });
  try {
    await send();
  } catch (error) {
    setTimeout(() => send().catch(() => {}), 1500);
  }
}

function setStatus(text, kind) {
  const holder = $("toolbar-status");
  holder.innerHTML = "";
  if (!text) return;
  const dot = el("span", "dot" + (kind ? " " + kind : ""));
  holder.append(dot, el("span", null, text));
}

const formatBytes = (value) => {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const size = value / Math.pow(1024, index);
  return `${size >= 10 || index === 0 ? Math.round(size) : size.toFixed(1)} ${units[index]}`;
};

const plural = (count, one, many) => `${count} ${count === 1 ? one : many}`;

/* ── Views ──────────────────────────────────────────────────────────── */

function showView(name) {
  for (const tab of document.querySelectorAll(".segmented [data-view]")) {
    tab.setAttribute("aria-selected", String(tab.dataset.view === name));
  }
  $("view-collect").hidden = name !== "collect";
  $("view-anonymize").hidden = name !== "anonymize";
  $("toolbar-sub").textContent =
    name === "collect" ? "Logs nach Tag und Logart sammeln" : "Werte ersetzen, bevor etwas das Haus verlässt";
}

/* ── Dialogs ────────────────────────────────────────────────────────── */

function askPassword(title, hint) {
  return new Promise((resolve) => {
    const dialog = $("password");
    $("password-title").textContent = title;
    $("password-hint").textContent = hint || "Mindestens zwölf Zeichen.";
    $("password-error").hidden = true;
    const input = $("password-value");
    input.value = "";
    const accept = () => {
      if (input.value.length < 12) {
        $("password-error").textContent = "Das Kennwort muss mindestens zwölf Zeichen lang sein.";
        $("password-error").hidden = false;
        return;
      }
      dialog.close("ok");
    };
    $("password-accept").onclick = accept;
    input.onkeydown = (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        accept();
      }
    };
    dialog.onclose = () => resolve(dialog.returnValue === "ok" ? input.value : null);
    dialog.showModal();
    input.focus();
  });
}

function askConfirm(title, text, acceptLabel) {
  return new Promise((resolve) => {
    const dialog = $("confirm");
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    $("confirm-accept").textContent = acceptLabel || "Fortfahren";
    $("confirm-accept").onclick = () => dialog.close("ok");
    dialog.onclose = () => resolve(dialog.returnValue === "ok");
    dialog.showModal();
  });
}

async function pickPath({ kind, title, startPath, suggestedName }) {
  if (state.info && state.info.nativeDialogs) {
    const native = await api("/api/pick", { kind });
    if (native.supported) return kind === "files" ? native.paths : native.paths[0] || null;
  }
  return browseDialog({ kind, title, startPath, suggestedName });
}

function browseDialog({ kind, title, startPath, suggestedName }) {
  return new Promise(async (resolve) => {
    const dialog = $("browser");
    const list = $("browser-list");
    const pathInput = $("browser-path");
    const selected = new Set();
    let current = startPath || (state.info && state.info.home) || "";

    $("browser-title").textContent = title || "Auswählen";
    $("browser-name-field").hidden = kind !== "save";
    $("browser-name").value = suggestedName || "";
    $("browser-note").textContent =
      kind === "dir" ? "Ordner wählen oder in einen Ordner wechseln." : kind === "files" ? "Mehrfachauswahl möglich." : "";

    const places = await api("/api/roots", {});
    const nav = $("browser-places");
    nav.innerHTML = "";
    for (const place of places.places) {
      const button = el("button", null, place.label);
      button.type = "button";
      button.onclick = () => load(place.path);
      nav.append(button);
    }

    async function load(path) {
      const data = await api("/api/browse", { path });
      current = data.path;
      pathInput.value = data.path;
      selected.clear();
      list.innerHTML = "";
      if (data.parent) {
        const up = el("li");
        up.append(el("span", "icon", "↰"), el("span", "name", ".."));
        up.onclick = () => load(data.parent);
        list.append(up);
      }
      for (const entry of data.entries) {
        if (kind === "dir" && entry.kind !== "dir") continue;
        const row = el("li");
        row.append(
          el("span", "icon", entry.kind === "dir" ? "▸" : entry.kind === "zip" ? "◫" : "▫"),
          el("span", "name", entry.name)
        );
        if (entry.size !== undefined) row.append(el("span", "meta", formatBytes(entry.size)));
        row.onclick = () => {
          if (entry.kind === "dir") {
            load(entry.path);
            return;
          }
          if (kind === "files") {
            if (selected.has(entry.path)) selected.delete(entry.path);
            else selected.add(entry.path);
          } else {
            selected.clear();
            selected.add(entry.path);
            if (kind === "save") $("browser-name").value = entry.name;
          }
          for (const item of list.children) item.removeAttribute("aria-selected");
          for (const item of list.children) {
            const label = item.querySelector(".name");
            if (label && selected.has(entry.path) && label.textContent === entry.name) {
              item.setAttribute("aria-selected", "true");
            }
          }
          $("browser-note").textContent = selected.size ? plural(selected.size, "Eintrag", "Einträge") + " gewählt" : "";
        };
        list.append(row);
      }
    }

    $("browser-go").onclick = () => load(pathInput.value);
    pathInput.onkeydown = (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        load(pathInput.value);
      }
    };
    $("browser-accept").onclick = () => {
      if (kind === "dir") dialog.close(JSON.stringify([current]));
      else if (kind === "save") dialog.close(JSON.stringify([joinPath(current, $("browser-name").value)]));
      else dialog.close(JSON.stringify([...selected]));
    };
    dialog.onclose = () => {
      let value = [];
      try {
        value = JSON.parse(dialog.returnValue || "[]");
      } catch (error) {
        value = [];
      }
      resolve(kind === "files" ? value : value[0] || null);
    };
    await load(current);
    dialog.showModal();
  });
}

function joinPath(folder, name) {
  if (!name) return folder;
  const separator = folder.includes("\\") ? "\\" : "/";
  return folder.replace(/[\\/]+$/, "") + separator + name;
}

/* ── Selection transfer ─────────────────────────────────────────────── */

// The chosen cells travel in pieces. On machines where larger local POST bodies
// are dropped before they reach the service, a big selection would otherwise
// fail as a bare "Failed to fetch"; the chunk size halves itself until it fits.
async function uploadSelection(pairs) {
  const id = `sel-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  let chunkSize = Math.min(25, pairs.length) || 1;
  let sent = 0;
  let reset = true;
  while (sent < pairs.length) {
    const chunk = pairs.slice(sent, sent + chunkSize);
    try {
      await api("/api/selection", { id, pairs: chunk, reset }, 2);
      sent += chunk.length;
      reset = false;
    } catch (error) {
      if (error.ok === false || error.error || chunkSize === 1) throw error;
      chunkSize = Math.max(1, Math.floor(chunkSize / 2));
      await reportToLog("info", `Auswahl-Übertragung auf ${chunkSize} Zelle(n) je Anfrage verkleinert`, "selection");
    }
  }
  return id;
}

// Some endpoint filters refuse requests by words in the path, such as
// "collect", whatever the body holds. The same handler answers under a second,
// plainer name, so a blocked path costs one extra attempt instead of the run.
async function apiAnyRoute(routes, body, context) {
  let lastError;
  for (let index = 0; index < routes.length; index += 1) {
    const route = routes[index];
    const last = index === routes.length - 1;
    try {
      const data = await api(route, body, last ? 3 : 1);
      if (index > 0) {
        await reportToLog("info", `${routes[0]} war nicht erreichbar, ${route} hat funktioniert`, context);
      }
      return data;
    } catch (error) {
      if (error.ok === false || error.error) throw error;
      lastError = error;
    }
  }
  throw lastError;
}

// A request the service never logs did not arrive at all. The browser cannot
// tell which half is to blame, so ask the service directly: the same payload
// under a route that demonstrably works, and the failing route with an empty
// payload. Whichever of the two arrives clears its half.
async function diagnoseUnreachable(route, body) {
  const size = JSON.stringify(body || {}).length;
  const verdict = [];
  try {
    await apiOnce("/api/echo", body);
    verdict.push(`derselbe Inhalt (${size} B) unter /api/echo: angekommen`);
  } catch (error) {
    verdict.push(`derselbe Inhalt (${size} B) unter /api/echo: ${error.message}`);
  }
  try {
    await apiOnce(route, {});
    verdict.push(`${route} mit leerem Inhalt: angekommen`);
  } catch (error) {
    const arrived = error.ok === false || error.error;
    verdict.push(`${route} mit leerem Inhalt: ${arrived ? "angekommen, vom Dienst abgelehnt" : error.message}`);
  }
  await reportToLog("warn", verdict.join(" | "), "diagnose");
}

/* ── Jobs ───────────────────────────────────────────────────────────── */

async function runJob(jobId, { progressEl, noteEl, cancelEl, onProgress }) {
  if (progressEl) progressEl.hidden = false;
  if (cancelEl) cancelEl.hidden = false;
  // A long run must survive a dropped poll: the work continues in the local
  // process, so keep asking for a while before giving up on it.
  const maxFailures = 40;
  let failures = 0;
  let polls = 0;
  try {
    while (true) {
      let job;
      try {
        job = await api("/api/job", { id: jobId });
        failures = 0;
      } catch (error) {
        failures += 1;
        if (failures > maxFailures) {
          throw new Error(
            `Verbindung zum lokalen Dienst verloren (${error.message}). Der Lauf kann im Hintergrund ` +
              `weiterlaufen - prüfe das Konsolenfenster und das Ziel.`
          );
        }
        if (noteEl) noteEl.textContent = `Verbindung unterbrochen, neuer Versuch (${failures}) ...`;
        await new Promise((resolve) => setTimeout(resolve, 500));
        continue;
      }
      const percent = Math.round((job.progress || 0) * 100);
      if (progressEl) progressEl.firstElementChild.style.width = percent + "%";
      if (noteEl) noteEl.textContent = job.message || "";
      if (onProgress) onProgress(job);
      if (job.status !== "running") return job;
      // Responsive at the start, then calmer: a long run does not need five
      // requests per second.
      polls += 1;
      await new Promise((resolve) => setTimeout(resolve, polls < 20 ? 250 : 750));
    }
  } finally {
    if (progressEl) progressEl.hidden = true;
    if (cancelEl) cancelEl.hidden = true;
  }
}

/* ── Collect ────────────────────────────────────────────────────────── */

function renderSources() {
  const list = $("collect-sources");
  list.innerHTML = "";
  for (const source of state.collect.sources) {
    const row = el("li");
    const remove = el("button", "btn btn-quiet", "Entfernen");
    remove.onclick = () => {
      state.collect.sources = state.collect.sources.filter((item) => item !== source);
      renderSources();
    };
    row.append(el("span", "icon", source.toLowerCase().endsWith(".zip") ? "◫" : "▸"), el("span", "name", source), remove);
    list.append(row);
  }
  $("collect-sources-empty").hidden = state.collect.sources.length > 0;
}

function cellKey(type, day) {
  return type + "\u0000" + day;
}

function renderMatrix() {
  const matrix = state.collect.matrix;
  const table = $("matrix");
  table.innerHTML = "";
  if (!matrix || !matrix.types.length) {
    $("matrix-wrap").hidden = true;
    $("matrix-footer").hidden = true;
    $("matrix-empty").hidden = false;
    $("matrix-empty").textContent = matrix
      ? "In den Quellen wurden keine datierten Logdateien gefunden."
      : "Nach dem Durchsuchen erscheint hier, welche Logarten an welchen Tagen vorliegen.";
    return;
  }
  $("matrix-wrap").hidden = false;
  $("matrix-footer").hidden = false;
  $("matrix-empty").hidden = true;

  const head = el("thead");
  const headRow = el("tr");
  headRow.append(el("th", null, "Logart"));
  for (const day of matrix.days) {
    const th = el("th");
    const button = el("button", null, day.slice(5).replace("-", "."));
    button.type = "button";
    button.title = `${day} – ganze Spalte umschalten`;
    button.onclick = () => toggleGroup(matrix.types.map((type) => cellKey(type, day)));
    th.append(button);
    headRow.append(th);
  }
  head.append(headRow);
  table.append(head);

  const body = el("tbody");
  for (const type of matrix.types) {
    const row = el("tr");
    const rowHead = el("th");
    const rowButton = el("button", null, type);
    rowButton.type = "button";
    rowButton.title = `${type} – ganze Zeile umschalten`;
    rowButton.onclick = () => toggleGroup(matrix.days.map((day) => cellKey(type, day)));
    rowHead.append(rowButton);
    row.append(rowHead);
    for (const day of matrix.days) {
      const cell = (matrix.cells[type] || {})[day];
      const td = el("td");
      if (!cell) {
        td.className = "empty-cell";
        td.textContent = "·";
      } else {
        const key = cellKey(type, day);
        if (state.collect.selection.has(key)) td.classList.add("on");
        const button = el("button", null, String(cell[0]));
        button.type = "button";
        button.title = `${type} am ${day}: ${plural(cell[0], "Datei", "Dateien")}, ${formatBytes(cell[1])}`;
        button.onclick = () => {
          if (state.collect.selection.has(key)) state.collect.selection.delete(key);
          else state.collect.selection.add(key);
          renderMatrix();
        };
        td.append(button);
      }
      row.append(td);
    }
    body.append(row);
  }
  table.append(body);
  renderSelectionSummary();
  updateDayScroll();
}

// The day columns rarely fit next to each other. Paging buttons work whatever
// the browser does with its scrollbars; they step by the visible width minus
// the type column, which stays pinned on the left.
function scrollDays(direction) {
  const wrap = $("matrix-wrap");
  const pinned = wrap.querySelector("thead th");
  const step = Math.max(120, wrap.clientWidth - (pinned ? pinned.offsetWidth : 0) - 40);
  wrap.scrollBy({ left: direction * step, behavior: "smooth" });
}

function updateDayScroll() {
  const wrap = $("matrix-wrap");
  const holder = $("matrix-scroll");
  const overflowing = !wrap.hidden && wrap.scrollWidth > wrap.clientWidth + 1;
  holder.hidden = !overflowing;
  if (!overflowing) return;
  holder.querySelector('[data-action="days-back"]').disabled = wrap.scrollLeft <= 0;
  holder.querySelector('[data-action="days-forward"]').disabled =
    wrap.scrollLeft + wrap.clientWidth >= wrap.scrollWidth - 1;
}

function toggleGroup(keys) {
  const available = keys.filter((key) => {
    const [type, day] = key.split("\u0000");
    return (state.collect.matrix.cells[type] || {})[day];
  });
  const allOn = available.every((key) => state.collect.selection.has(key));
  for (const key of available) {
    if (allOn) state.collect.selection.delete(key);
    else state.collect.selection.add(key);
  }
  renderMatrix();
}

function renderSelectionSummary() {
  const matrix = state.collect.matrix;
  let files = 0;
  let bytes = 0;
  for (const key of state.collect.selection) {
    const [type, day] = key.split("\u0000");
    const cell = (matrix.cells[type] || {})[day];
    if (cell) {
      files += cell[0];
      bytes += cell[1];
    }
  }
  const summary = $("selection-summary");
  summary.innerHTML = "";
  if (!files) {
    summary.append(
      el("span", null, `Nichts ausgewählt. Insgesamt ${plural(matrix.total, "Datei", "Dateien")} in `),
      el("b", null, plural(matrix.types.length, "Logart", "Logarten")),
      el("span", null, ` an ${plural(matrix.days.length, "Tag", "Tagen")}.`)
    );
  } else {
    summary.append(
      el("b", null, plural(files, "Datei", "Dateien")),
      el("span", null, ` ausgewählt · ${formatBytes(bytes)} von ${formatBytes(totalBytes())}`)
    );
  }
  if (matrix.undated) {
    summary.append(el("span", null, ` · ${plural(matrix.undated, "Datei", "Dateien")} ohne Datum übersprungen`));
  }
}

function totalBytes() {
  let bytes = 0;
  const matrix = state.collect.matrix;
  for (const type of Object.keys(matrix.cells)) {
    for (const day of Object.keys(matrix.cells[type])) bytes += matrix.cells[type][day][1];
  }
  return bytes;
}

async function scanSources() {
  if (!state.collect.sources.length) {
    setStatus("Zuerst eine Quelle hinzufügen", "error");
    return;
  }
  setStatus("Quellen werden gelesen …", "busy");
  const { job } = await api("/api/scan", {
    sources: state.collect.sources,
    containerFallback: $("collect-fallback").checked,
  });
  const finished = await runJob(job, { progressEl: $("collect-progress"), noteEl: $("collect-note") });
  if (finished.status !== "done") {
    setStatus(finished.error || "Abgebrochen", "error");
    return;
  }
  state.collect.matrix = finished.result;
  state.collect.selection = new Set();
  renderMatrix();
  const errors = finished.result.archiveErrors || [];
  setStatus(
    `${plural(finished.result.total, "Datei", "Dateien")} gefunden` + (errors.length ? `, ${errors.length} ZIP-Fehler` : ""),
    errors.length ? "error" : null
  );
}

async function runCollect() {
  const target = $("collect-target").value.trim();
  if (!state.collect.sources.length) return setStatus("Zuerst eine Quelle hinzufügen", "error");
  if (!state.collect.selection.size) return setStatus("Zuerst Tage und Logarten auswählen", "error");
  if (!target) return setStatus("Zuerst ein Ziel wählen", "error");

  const pairs = [...state.collect.selection].map((key) => key.split("\u0000"));
  setStatus("Dateien werden kopiert …", "busy");
  $("collect-result").hidden = true;
  await reportToLog("info", `sende Sammelauftrag: ${pairs.length} Zelle(n), Ziel ${target}`, "collect");
  const selectionId = await uploadSelection(pairs);
  const request = {
    sources: state.collect.sources,
    selectionId,
    target,
    asArchive: state.collect.mode === "archive",
    containerFallback: $("collect-fallback").checked,
    force: $("collect-force").checked,
  };
  let job;
  try {
    ({ job } = await apiAnyRoute(["/api/collect", "/api/start"], request, "collect"));
  } catch (error) {
    if (!(error.ok === false || error.error)) await diagnoseUnreachable("/api/collect", request);
    throw error;
  }
  state.collect.job = job;
  const finished = await runJob(job, {
    progressEl: $("collect-progress"),
    noteEl: $("collect-note"),
    cancelEl: document.querySelector('[data-action="cancel"]'),
  });
  state.collect.job = null;
  $("collect-note").textContent = "";
  if (finished.status === "error") {
    showCollectResult(null, finished.error);
    setStatus("Fehlgeschlagen", "error");
    return;
  }
  if (finished.status === "cancelled") {
    showCollectResult(null, finished.error || "Abgebrochen. Bereits kopierte Dateien bleiben zur Kontrolle liegen.");
    setStatus("Abgebrochen", "error");
    return;
  }
  showCollectResult(finished.result, null);
  setStatus("Fertig", null);
}

function showCollectResult(result, error) {
  const body = $("collect-result-body");
  body.innerHTML = "";
  $("collect-result").hidden = false;
  if (error) {
    body.append(el("p", "error-line", error));
    return;
  }
  const stats = el("div", "stats");
  const add = (label, value) => {
    const chip = el("span", "stat");
    chip.append(el("b", null, String(value)), el("span", null, label));
    stats.append(chip);
  };
  add("übernommen", result.selected);
  add("Dubletten", result.duplicates);
  add("ZIP-Fehler", result.archive_errors);
  add("geprüft", result.files_inspected);
  body.append(stats);
  const target = result.output_archive || result.collection_directory;
  body.append(line("Ergebnis", target), line("Umfang", formatBytes(result.bytes_written)), line("Manifest (nur lokal)", result.manifest));
  body.append(el("p", "warn-line", "Vor der Weitergabe anonymisieren und stichprobenartig prüfen."));
}

function line(label, value) {
  const node = el("p", "result-line");
  node.append(el("b", null, label + ": "), el("span", null, value || "—"));
  return node;
}

/* ── Anonymize ──────────────────────────────────────────────────────── */

function anonOptions() {
  return {
    mode: document.querySelector('input[name="anon-method"]:checked').value,
    keepPrivateIp: $("opt-keep-private").checked,
    anonymizeHostname: $("opt-hostnames").checked,
    useStore: $("opt-store").checked,
    keepDomains: $("opt-keep-domains").value.split(/[,;]/).map((item) => item.trim()).filter(Boolean),
    detectPersonal: $("opt-personal").checked,
    encoding: $("opt-encoding").value,
    restore: $("anon-restore").checked,
  };
}

let previewTimer = null;
function schedulePreview() {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(renderPreview, 220);
}

async function renderPreview() {
  const text = $("anon-input").value;
  const output = $("anon-output");
  $("anon-output-label").textContent = $("anon-restore").checked ? "Zurückgewandelt" : "Anonymisiert";
  if (!text.trim()) {
    output.innerHTML = "";
    output.append(el("span", "placeholder", "Die Vorschau erscheint, sobald links Text steht. Der Store wird dabei nicht verändert."));
    $("anon-legend").innerHTML = "";
    return;
  }
  let data;
  try {
    data = await api("/api/preview", Object.assign(anonOptions(), { text, limit: 200 }));
  } catch (error) {
    output.innerHTML = "";
    output.append(el("span", "error-line", error.message));
    return;
  }
  output.innerHTML = "";
  closeMarkPop();
  output.classList.toggle("editable", !$("anon-restore").checked && state.lists.available);
  for (const segments of data.lines) {
    const line = el("span", "line");
    for (const segment of segments) {
      if (!segment.category) {
        line.append(document.createTextNode(segment.text));
        continue;
      }
      const mark = el("mark", null, segment.text);
      mark.dataset.category = segment.category;
      mark.dataset.original = segment.original;
      mark.dataset.tag = CATEGORY_TAGS[segment.category] || "?";
      mark.title = `${CATEGORY_LABELS[segment.category] || segment.category}: ${segment.original}`;
      line.append(mark);
    }
    output.append(line);
  }
  renderLegend(data.stats, data.restored, data.unresolved);
}

function renderLegend(stats, restored, unresolved) {
  const legend = $("anon-legend");
  legend.innerHTML = "";
  if ($("anon-restore").checked) {
    legend.append(el("span", null, `${plural(restored, "Platzhalter", "Platzhalter")} zurückgewandelt`));
    if (unresolved) legend.append(el("span", null, `${unresolved} unbekannt und unverändert gelassen`));
    return;
  }
  for (const [category, label] of Object.entries(CATEGORY_LABELS)) {
    const count = stats[category] || 0;
    if (!count || !CATEGORY_COLORS[category]) continue;
    const item = el("span");
    const swatch = el("i");
    swatch.style.background = `var(--${CATEGORY_COLORS[category]})`;
    item.append(swatch, el("span", null, `${label} · ${count}`));
    legend.append(item);
  }
  if (!legend.children.length) legend.append(el("span", null, "Keine zu ersetzenden Werte gefunden."));
}

/* ── Own terms and never replace ────────────────────────────────────── */

async function loadLists() {
  try {
    Object.assign(state.lists, await api("/api/lists", {}), { available: true });
  } catch (error) {
    state.lists.available = false;
  }
  renderLists();
}

function renderLists() {
  const terms = $("term-list");
  const ignored = $("ignore-list");
  terms.innerHTML = "";
  ignored.innerHTML = "";
  for (const term of state.lists.terms) {
    terms.append(chip(term.value, term.token, () => changeList("term", "remove", term.value)));
  }
  for (const pattern of state.lists.patterns) {
    terms.append(chip(`/${pattern}/`, "Muster", () => changeList("pattern", "remove", pattern)));
  }
  for (const value of state.lists.ignored) {
    ignored.append(chip(value, "", () => changeList("ignore", "remove", value)));
  }
  $("ignore-note").textContent = state.lists.available
    ? "In der Vorschau auf eine Ersetzung klicken, um sie hier aufzunehmen."
    : "Die Listen liegen im Store. Erst den Store entsperren.";
  $("term-input").disabled = !state.lists.available;
  document.querySelector('[data-action="term-add"]').disabled = !state.lists.available;
}

function chip(text, note, onRemove) {
  const item = el("li", "chip");
  item.append(el("span", "chip-text", text));
  if (note) item.append(el("span", "chip-token", note));
  const remove = el("button", null, "×");
  remove.type = "button";
  remove.title = `„${text}“ entfernen`;
  remove.setAttribute("aria-label", `„${text}“ entfernen`);
  remove.onclick = () => onRemove().catch((error) => setStatus(error.message, "error"));
  item.append(remove);
  return item;
}

async function changeList(kind, action, value) {
  const result = await api("/api/lists/change", { kind, action, value });
  Object.assign(state.lists, result, { available: true });
  renderLists();
  schedulePreview();
  refreshStore();
}

async function addTerm(value) {
  value = (value || "").trim();
  if (!value) return setStatus("Erst einen Begriff eingeben oder Text markieren", "error");
  if (value.includes("\n")) return setStatus("Bitte nur eine Zeile markieren", "error");
  await changeList("term", "add", value);
  setStatus(`„${value}“ wird ab jetzt immer ersetzt`, null);
}

// The text marked in the original or in the preview, if any.
function markedText() {
  const input = $("anon-input");
  if (document.activeElement === input && input.selectionEnd > input.selectionStart) {
    return input.value.slice(input.selectionStart, input.selectionEnd);
  }
  const selection = window.getSelection();
  if (selection && !selection.isCollapsed && $("anon-output").contains(selection.anchorNode)) {
    return selection.toString();
  }
  return "";
}

let lastMarked = "";
function updateMarkedButton() {
  const marked = markedText().trim();
  if (marked) lastMarked = marked;
  // Clicking the button moves the focus away; keep what was marked just before.
  const button = document.querySelector('[data-action="term-from-selection"]');
  button.disabled = !(marked || (lastMarked && document.activeElement === button)) || !state.lists.available;
}

function openMarkPop(mark) {
  const pop = $("mark-pop");
  const category = mark.dataset.category;
  const original = mark.dataset.original || "";
  pop.innerHTML = "";
  pop.append(el("div", "pop-original", original));
  const meta = el("div", "pop-meta");
  meta.append(document.createTextNode(`${CATEGORY_LABELS[category] || category} → `), el("code", null, mark.textContent));
  pop.append(meta);
  const actions = el("div", "card-actions card-actions-start");
  const never = el("button", "btn", "Nie ersetzen");
  never.onclick = () => changeList("ignore", "add", original).then(closeMarkPop).catch((error) => setStatus(error.message, "error"));
  actions.append(never);
  const isTerm = state.lists.terms.some((term) => term.value.toLowerCase() === original.toLowerCase());
  if (isTerm) {
    const drop = el("button", "btn btn-quiet", "Nicht mehr als Begriff");
    drop.onclick = () => changeList("term", "remove", original).then(closeMarkPop).catch((error) => setStatus(error.message, "error"));
    actions.append(drop);
  }
  const close = el("button", "btn btn-quiet", "Schließen");
  close.onclick = closeMarkPop;
  actions.append(close);
  pop.append(actions);

  const pane = pop.parentElement.getBoundingClientRect();
  const box = mark.getBoundingClientRect();
  pop.hidden = false;
  const left = Math.min(Math.max(8, box.left - pane.left), pane.width - pop.offsetWidth - 8);
  pop.style.left = `${Math.max(8, left)}px`;
  pop.style.top = `${box.bottom - pane.top + 6}px`;
  never.focus();
}

function closeMarkPop() {
  const pop = $("mark-pop");
  if (pop) pop.hidden = true;
}

function renderAnonFiles() {
  const list = $("anon-files");
  list.innerHTML = "";
  for (const file of state.anon.files) {
    const row = el("li");
    const remove = el("button", "btn btn-quiet", "Entfernen");
    remove.onclick = () => {
      state.anon.files = state.anon.files.filter((item) => item !== file);
      renderAnonFiles();
    };
    row.append(el("span", "icon", "▫"), el("span", "name", file), remove);
    list.append(row);
  }
  $("anon-files-empty").hidden = state.anon.files.length > 0;
}

async function runAnonymize() {
  const options = anonOptions();
  if (state.anon.mode === "text") {
    const text = $("anon-input").value;
    if (!text.trim()) return setStatus("Zuerst Text einfügen", "error");
    setStatus("Wird verarbeitet …", "busy");
    const data = await api("/api/anonymize/text", Object.assign(options, { text }));
    state.anon.lastResult = data.text;
    await renderPreview();
    showAnonResult(data, null);
    setStatus(options.restore ? "Zurückgewandelt" : "Anonymisiert", null);
    try {
      await navigator.clipboard.writeText(data.text);
      $("anon-note").textContent = "Ergebnis in der Zwischenablage.";
    } catch (error) {
      $("anon-note").textContent = "";
    }
    await refreshStore();
    return;
  }

  if (!state.anon.files.length) return setStatus("Zuerst Dateien wählen", "error");
  setStatus("Dateien werden verarbeitet …", "busy");
  $("anon-result").hidden = true;
  const { job } = await api(
    "/api/anonymize/files",
    Object.assign(options, {
      files: state.anon.files,
      output: $("anon-output-dir").value.trim(),
      force: $("anon-force").checked,
    })
  );
  state.anon.job = job;
  const finished = await runJob(job, {
    progressEl: $("anon-progress"),
    noteEl: $("anon-note"),
    cancelEl: document.querySelector('[data-action="anon-cancel"]'),
  });
  state.anon.job = null;
  if (finished.status === "done") {
    showAnonResult(finished.result, null);
    setStatus("Fertig", null);
  } else {
    showAnonResult(null, finished.error || "Abgebrochen");
    setStatus(finished.status === "cancelled" ? "Abgebrochen" : "Fehlgeschlagen", "error");
  }
  await refreshStore();
}

function showAnonResult(result, error) {
  const body = $("anon-result-body");
  body.innerHTML = "";
  $("anon-result").hidden = false;
  if (error) {
    body.append(el("p", "error-line", error));
    return;
  }
  const stats = el("div", "stats");
  for (const [category, label] of Object.entries(CATEGORY_LABELS)) {
    const count = (result.stats || {})[category] || 0;
    if (!count) continue;
    const chip = el("span", "stat");
    chip.append(el("b", null, String(count)), el("span", null, label));
    stats.append(chip);
  }
  if (result.restored) {
    const chip = el("span", "stat");
    chip.append(el("b", null, String(result.restored)), el("span", null, "zurückgewandelt"));
    stats.append(chip);
  }
  if (stats.children.length) body.append(stats);

  for (const file of result.files || []) {
    body.append(line(file.target.split(/[\\/]/).pop(), `${file.lines} Zeilen · ${file.target}`));
  }
  if (result.unresolved) {
    body.append(el("p", "warn-line", `${result.unresolved} Platzhalter waren im Store unbekannt und blieben unverändert.`));
  }
  if (result.backup) body.append(line("Store-Sicherung", result.backup));
  if (result.mappingCsv) body.append(el("p", "warn-line", `Zuordnungsdatei geschrieben: ${result.mappingCsv} – niemals weitergeben.`));
  body.append(el("p", "warn-line", "Ergebnis vor der Weitergabe sichtprüfen; automatische Erkennung ersetzt keine Kontrolle."));
}

/* ── Store ──────────────────────────────────────────────────────────── */

async function refreshStore(password) {
  const info = await api("/api/store/info", password ? { password } : {});
  const badge = $("store-badge");
  const summary = $("store-summary");
  const counts = $("store-counts");
  loadLists(); // the lists live in the store and follow it
  counts.innerHTML = "";
  $("store-path").textContent = info.path;
  // Without DPAPI the store needs a password, also when it does not exist yet.
  const unlock = document.querySelector('[data-action="store-unlock"]');
  const needsPassword = (info.exists && !info.readable) || (!info.exists && !state.info.dpapi);
  unlock.hidden = !needsPassword;
  unlock.textContent = info.exists ? "Entsperren …" : "Kennwort setzen …";

  if (!info.exists) {
    badge.textContent = "leer";
    badge.className = "badge off";
    summary.textContent = "Noch keine Zuordnung gespeichert. Die Nummerierung beginnt bei 001.";
    return;
  }
  if (!info.readable) {
    badge.textContent = "gesperrt";
    badge.className = "badge warn";
    summary.textContent = info.message;
    return;
  }
  badge.textContent = info.protection === "DPAPI-CurrentUser" ? "DPAPI" : info.protection === "Unprotected" ? "ungeschützt" : "Kennwort";
  badge.className = "badge" + (info.protection === "Unprotected" ? " warn" : "");
  summary.textContent = `${plural(info.total, "Zuordnung", "Zuordnungen")} gespeichert, zuletzt ${info.updated || "unbekannt"}. Gleiche Werte behalten ihren Platzhalter.`;
  for (const [category, count] of Object.entries(info.counts || {})) {
    if (!count) continue;
    const box = el("div");
    box.append(el("b", null, String(count)), el("span", null, STORE_LABELS[category] || category));
    counts.append(box);
  }
}

async function exportStore() {
  const target = await pickPath({ kind: "save", title: "Store exportieren", suggestedName: "anonymization-backup.anonstore" });
  if (!target) return;
  const password = await askPassword("Store exportieren", "Kennwort für die Sicherung, mindestens zwölf Zeichen. Datei und Kennwort getrennt übermitteln.");
  if (!password) return;
  try {
    await api("/api/store/export", { path: target, password, force: true });
    setStatus("Store exportiert", null);
    $("anon-note").textContent = `Sicherung: ${target}`;
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function importStore() {
  const source = await pickPath({ kind: "files", title: "Store importieren" });
  const path = Array.isArray(source) ? source[0] : source;
  if (!path) return;
  const ok = await askConfirm(
    "Store importieren",
    "Der vorhandene lokale Store wird ersetzt. Vorher wird automatisch eine Sicherung daneben abgelegt.",
    "Importieren"
  );
  if (!ok) return;
  const password = await askPassword("Store importieren", "Kennwort der Sicherungsdatei.");
  if (!password) return;
  try {
    const data = await api("/api/store/import", { path, password });
    setStatus("Store importiert", null);
    if (data.backup) $("anon-note").textContent = `Vorheriger Store gesichert: ${data.backup}`;
    await refreshStore();
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function resetStore() {
  const ok = await askConfirm(
    "Store zurücksetzen",
    "Alle gespeicherten Zuordnungen werden entfernt und die Nummerierung beginnt wieder bei 001. Eine Sicherung wird automatisch daneben abgelegt.",
    "Zurücksetzen"
  );
  if (!ok) return;
  const data = await api("/api/store/reset", {});
  setStatus("Store zurückgesetzt", null);
  if (data.backup) $("anon-note").textContent = `Sicherung: ${data.backup}`;
  await refreshStore();
}

/* ── Wiring ─────────────────────────────────────────────────────────── */

const actions = {
  "add-folder": async () => {
    const path = await pickPath({ kind: "dir", title: "Quellordner wählen" });
    if (path && !state.collect.sources.includes(path)) {
      state.collect.sources.push(path);
      renderSources();
    }
  },
  "add-files": async () => {
    const paths = await pickPath({ kind: "files", title: "ZIP-Dateien oder Logs wählen" });
    for (const path of paths || []) if (!state.collect.sources.includes(path)) state.collect.sources.push(path);
    renderSources();
  },
  scan: scanSources,
  "term-add": () => addTerm($("term-input").value).then(() => ($("term-input").value = "")),
  "term-from-selection": () => addTerm(markedText() || lastMarked).then(() => (lastMarked = "")),
  "days-back": () => scrollDays(-1),
  "days-forward": () => scrollDays(1),
  "select-all": () => {
    const matrix = state.collect.matrix;
    if (!matrix) return;
    for (const type of matrix.types) {
      for (const day of matrix.days) if ((matrix.cells[type] || {})[day]) state.collect.selection.add(cellKey(type, day));
    }
    renderMatrix();
  },
  "select-none": () => {
    state.collect.selection.clear();
    renderMatrix();
  },
  "pick-target": async () => {
    const archive = state.collect.mode === "archive";
    const path = await pickPath({
      kind: archive ? "save" : "dir",
      title: archive ? "Zielarchiv wählen" : "Sammelordner wählen",
      suggestedName: archive ? "Logs.zip" : undefined,
    });
    if (path) $("collect-target").value = path;
  },
  collect: runCollect,
  cancel: async () => {
    if (state.collect.job) await api("/api/job/cancel", { id: state.collect.job });
  },
  "anon-add-files": async () => {
    const paths = await pickPath({ kind: "files", title: "Logdateien wählen" });
    for (const path of paths || []) if (!state.anon.files.includes(path)) state.anon.files.push(path);
    renderAnonFiles();
  },
  "anon-add-folder": async () => {
    const path = await pickPath({ kind: "dir", title: "Ordner mit Logdateien wählen" });
    if (!path) return;
    const data = await api("/api/browse", { path });
    for (const entry of data.entries) {
      if (entry.kind === "file" && /\.(log|txt)$/i.test(entry.name) && !state.anon.files.includes(entry.path)) {
        state.anon.files.push(entry.path);
      }
    }
    renderAnonFiles();
  },
  "pick-output": async () => {
    const path = await pickPath({ kind: "dir", title: "Ausgabeordner wählen" });
    if (path) $("anon-output-dir").value = path;
  },
  "anon-run": runAnonymize,
  "anon-cancel": async () => {
    if (state.anon.job) await api("/api/job/cancel", { id: state.anon.job });
  },
  "clear-text": () => {
    $("anon-input").value = "";
    schedulePreview();
  },
  "copy-result": async () => {
    const text = state.anon.lastResult || $("anon-output").textContent;
    try {
      await navigator.clipboard.writeText(text);
      $("anon-note").textContent = "Ergebnis in der Zwischenablage.";
    } catch (error) {
      $("anon-note").textContent = "Kopieren wurde vom Browser abgelehnt.";
    }
  },
  "store-unlock": async () => {
    const password = await askPassword(
      "Zuordnungsstore",
      "Kennwort dieses Stores. Ohne Windows-DPAPI wird die Zuordnung damit verschlüsselt abgelegt."
    );
    if (!password) return;
    try {
      await refreshStore(password);
      setStatus("Store entsperrt", null);
    } catch (error) {
      setStatus(error.message, "error");
    }
  },
  "connection-test": async () => {
    const sizes = [64, 256, 512, 1024, 2048, 4096, 8192, 16384, 65536];
    const results = [];
    setStatus("Verbindung wird getestet …", "busy");
    for (const size of sizes) {
      try {
        const data = await api("/api/echo", { pad: "x".repeat(size) }, 1);
        results.push([`${size} Bytes`, data.size === size ? "OK" : `FEHLER: ${data.size} angekommen`]);
      } catch (error) {
        results.push([`${size} Bytes`, `FEHLER: ${error.message}`]);
      }
    }
    const largest = results.filter((row) => row[1] === "OK").pop();
    results.push(["Größte funktionierende Anfrage", largest ? largest[0] : "keine"]);
    await reportToLog("info", results.map((row) => `${row[0]}=${row[1]}`).join("; "), "connection-test");

    const table = $("report-table");
    table.innerHTML = "";
    for (const [label, value] of results) {
      const line = el("tr");
      line.append(el("th", null, label), el("td", null, value));
      if (value.startsWith("FEHLER")) line.className = "bad";
      table.append(line);
    }
    $("report-title").textContent = "Verbindungstest";
    $("report-copy").textContent = "Als Text kopieren";
    $("report-copy").onclick = async () => {
      try {
        await navigator.clipboard.writeText(results.map((row) => `${row[0]}: ${row[1]}`).join("\n"));
        $("report-copy").textContent = "Kopiert";
      } catch (error) {
        $("report-copy").textContent = "Kopieren abgelehnt";
      }
    };
    $("report").showModal();
    setStatus(largest ? `Größte Anfrage: ${largest[0]}` : "Keine Anfrage kam durch", largest ? null : "error");
  },
  "store-check": async () => {
    const { report } = await api("/api/store/check", {});
    const table = $("report-table");
    table.innerHTML = "";
    for (const row of report) {
      const line = el("tr");
      line.append(el("th", null, row.label), el("td", null, row.value));
      if (/FAILED|fehlge/i.test(row.value)) line.className = "bad";
      table.append(line);
    }
    $("report-copy").onclick = async () => {
      const text = report.map((row) => `${row.label}: ${row.value}`).join("\n");
      try {
        await navigator.clipboard.writeText(text);
        $("report-copy").textContent = "Kopiert";
      } catch (error) {
        $("report-copy").textContent = "Kopieren abgelehnt";
      }
    };
    $("report-title").textContent = "Store-Diagnose";
    $("report-copy").textContent = "Als Text kopieren";
    $("report").showModal();
  },
  "store-export": exportStore,
  "store-import": importStore,
  "store-reset": resetStore,
};

document.addEventListener("click", (event) => {
  const trigger = event.target.closest("[data-action]");
  if (!trigger) return;
  const handler = actions[trigger.dataset.action];
  if (!handler) return;
  event.preventDefault();
  Promise.resolve(handler()).catch((error) => {
    setStatus(error.message, "error");
    reportToLog("error", error.message, trigger.dataset.action);
  });
});

$("matrix-wrap").addEventListener("scroll", updateDayScroll, { passive: true });
$("term-input").addEventListener("keydown", (event) => {
  if (event.key !== "Enter") return;
  event.preventDefault();
  actions["term-add"]().catch((error) => setStatus(error.message, "error"));
});
document.addEventListener("selectionchange", updateMarkedButton);
$("anon-output").addEventListener("click", (event) => {
  const mark = event.target.closest("mark");
  if (!mark || !$("anon-output").classList.contains("editable") || mark.dataset.category === "Restored") return;
  if (!window.getSelection().isCollapsed) return; // marking text, not choosing a replacement
  openMarkPop(mark);
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeMarkPop();
});
document.addEventListener("mousedown", (event) => {
  if (!event.target.closest("#mark-pop") && !event.target.closest("#anon-output mark")) closeMarkPop();
});
window.addEventListener("resize", updateDayScroll);

for (const tab of document.querySelectorAll(".segmented [data-view]")) {
  tab.onclick = () => showView(tab.dataset.view);
}

$("collect-mode").onclick = (event) => {
  const button = event.target.closest("[data-mode]");
  if (!button) return;
  state.collect.mode = button.dataset.mode;
  for (const item of $("collect-mode").children) item.setAttribute("aria-checked", String(item === button));
  $("collect-target-hint").textContent =
    state.collect.mode === "archive"
      ? "Ein ZIP mit LZMA-Kompression. 7-Zip wird dafür nicht benötigt."
      : "Ein leerer oder neuer Ordner. Die Originale bleiben unverändert.";
  $("collect-target").placeholder = state.collect.mode === "archive" ? "Zielarchiv wählen …" : "Zielordner wählen …";
};

$("anon-mode").onclick = (event) => {
  const button = event.target.closest("[data-mode]");
  if (!button) return;
  state.anon.mode = button.dataset.mode;
  for (const item of $("anon-mode").children) item.setAttribute("aria-checked", String(item === button));
  $("anon-text-panel").hidden = state.anon.mode !== "text";
  $("anon-files-panel").hidden = state.anon.mode !== "files";
};

$("anon-input").addEventListener("input", schedulePreview);
$("anon-restore").addEventListener("change", schedulePreview);
for (const id of ["opt-keep-private", "opt-hostnames", "opt-store", "opt-keep-domains", "opt-personal"]) {
  $(id).addEventListener("change", schedulePreview);
}
for (const radio of document.querySelectorAll('input[name="anon-method"]')) {
  radio.addEventListener("change", schedulePreview);
}

document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter" && state.anon.mode === "text") {
    event.preventDefault();
    runAnonymize().catch((error) => setStatus(error.message, "error"));
  }
});

(async function start() {
  try {
    state.info = await api("/api/state", {});
  } catch (error) {
    setStatus("Keine Verbindung zum lokalen Dienst", "error");
    return;
  }
  $("log-path").textContent = state.info.logPath || "(kein Protokoll)";
  showView("collect");
  renderSources();
  renderAnonFiles();
  await refreshStore();
  await renderPreview();
  setStatus("Bereit", null);
})();
