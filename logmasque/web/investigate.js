"use strict";

/* Log Investigator: search, timeline, entities, graph and the export for an
   outside analysis. Everything is computed by the local service from its
   index; this file only shows it. Original values appear here because this is
   the internal view. Only the export dialog produces text meant to leave the
   machine, and it never sends anything by itself. */

const INV_KINDS = {
  msgid: { label: "Message-ID", tag: "M", color: "purple" },
  queue: { label: "Queue-Datei", tag: "Q", color: "indigo" },
  session: { label: "Sitzung", tag: "S", color: "teal" },
  request: { label: "Request", tag: "R", color: "cyan" },
  email: { label: "E-Mail-Adresse", tag: "@", color: "green" },
  account: { label: "Konto", tag: "K", color: "green" },
  device: { label: "Gerät", tag: "G", color: "brown" },
  ipv4: { label: "IPv4-Adresse", tag: "4", color: "blue" },
  ipv6: { label: "IPv6-Adresse", tag: "6", color: "blue" },
  endpoint: { label: "IP und Port", tag: "P", color: "blue" },
  domain: { label: "Domain / Host", tag: "D", color: "orange" },
  host: { label: "Rechnername", tag: "H", color: "orange" },
  url: { label: "URL", tag: "U", color: "olive" },
  status: { label: "Statuscode", tag: "#", color: "label-tertiary" },
  code: { label: "Fehler-/Meldungscode", tag: "#", color: "label-tertiary" },
  pid: { label: "Prozess / Thread", tag: "T", color: "label-tertiary" },
  port: { label: "Port", tag: ":", color: "label-tertiary" },
};
// Shown in the graph unless asked for: names everybody shares add noise, not links.
const GRAPH_KINDS = ["msgid", "queue", "session", "request", "email", "account", "device", "ipv4", "ipv6", "endpoint", "domain", "host", "url"];
const GRAPH_DEFAULT = new Set(["msgid", "queue", "session", "request", "email", "account", "device", "ipv4", "ipv6"]);

const LEVELS = { 1: "direkt", 2: "stark", 3: "möglich" };
const LEVEL_TITLES = {
  1: "Direkt: gemeinsamer eindeutiger Bezeichner (gleiches Ereignis, gleiche Sitzung, gleicher Request oder Verarbeitungsblock, gleiche Message-ID oder Queue-Datei)",
  2: "Stark: gemeinsames Merkmal (Adresse, Konto, Gerät) in zeitlicher Nähe",
  3: "Möglich: ein Merkmal zeitlich entfernt, ein geteiltes Merkmal (z. B. NAT-Adresse) in zeitlicher Nähe, oder nur zeitliche Nähe. Kein Beleg für einen Zusammenhang.",
};
const TIME_FLAGS = {
  exact: { mark: "", title: "Zeitzone steht in der Zeile" },
  source: { mark: "", title: "Zeitzone der Quelle" },
  inferred: { mark: "≈", title: "Zeitzone aus anderen Logs dieser Untersuchung übernommen" },
  local: { mark: "≈", title: "Zeitzone dieses Rechners angenommen" },
  inherited: { mark: "↑", title: "Keine eigene Zeit, von der Zeile davor übernommen", warn: true },
  ambiguous: { mark: "?", title: "Zeitangabe mehrdeutig", warn: true },
  invalid: { mark: "!", title: "Zeitstempel ungültig: steht am Ende, nicht zeitlich einsortiert", warn: true },
  none: { mark: "–", title: "Ohne Zeitangabe: steht am Ende, nicht zeitlich einsortiert", warn: true },
};
const SEVERITIES = { 0: "Detail", 1: "Info", 2: "Warnung", 3: "Fehler" };

const inv = {
  loaded: false,
  current: null,
  overview: null,
  anchors: [],
  sources: new Set(),
  etypes: new Set(),
  offset: 0,
  limit: 200,
  result: null,
  context: null,
  selected: new Set(),
  eventId: null,
  entityId: null,
  graph: null,
  graphKinds: new Set(GRAPH_DEFAULT),
  job: null,
  scan: null,
  readyShown: false,
  searchedVersion: 0,
  suggest: { items: [], index: -1, timer: null, seq: 0 },
  searchSeq: 0,
};

const invApi = (route, body, attempts) => api("/api/inv/" + route, body, attempts);

/* ── Small helpers ───────────────────────────────────────────────────── */

function kindOf(kind) {
  return INV_KINDS[kind] || { label: kind, tag: "?", color: "label-tertiary" };
}

function entityChip(item, onClick) {
  const meta = kindOf(item.kind);
  const button = el("button", "ent" + (item.common ? " common" : "") + (item.generic ? " generic" : ""));
  button.type = "button";
  const tag = el("span", "k", meta.tag);
  button.style.setProperty("--c", `var(--${meta.color})`);
  const shown = item.display || item.value;
  button.append(tag, el("span", "v", shown));
  let title = `${meta.label}: ${shown}`;
  if (item.role && item.role !== "context") title += ` (Rolle: ${item.role})`;
  if (item.common) title += " · häufig, verknüpft nur in zeitlicher Nähe";
  if (item.generic) title += " · allgemeiner Wert, verknüpft nicht";
  button.title = title;
  if (onClick) {
    button.onclick = (event) => {
      event.stopPropagation();
      onClick(item);
    };
  }
  return button;
}

function levelBadge(level) {
  const badge = el("span", `lvl lvl-${level || 0}`, LEVELS[level] || "");
  if (level) badge.title = LEVEL_TITLES[level];
  return badge;
}

function formatOffset(minutes) {
  if (minutes === null || minutes === undefined || minutes === "") return "";
  const sign = minutes < 0 ? "-" : "+";
  const value = Math.abs(minutes);
  return `${sign}${String(Math.floor(value / 60)).padStart(2, "0")}:${String(value % 60).padStart(2, "0")}`;
}

function parseOffset(text) {
  const match = /^\s*(?:UTC|GMT)?\s*([+-])?(\d{1,2})(?::?(\d{2}))?\s*$/i.exec(text || "");
  if (!match) return null;
  const minutes = Number(match[2]) * 60 + Number(match[3] || 0);
  if (minutes > 14 * 60) return null;
  return match[1] === "-" ? -minutes : minutes;
}

const pad2 = (value) => String(value).padStart(2, "0");

function localInput(ms) {
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}T${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}

function localStamp(ms, withDate = true) {
  if (ms === null || ms === undefined) return "";
  const d = new Date(ms);
  const time = `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  return withDate ? `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${time}` : time;
}

function askText(title, hint, value) {
  return new Promise((resolve) => {
    const dialog = $("prompt");
    $("prompt-title").textContent = title;
    $("prompt-hint").textContent = hint || "";
    const input = $("prompt-value");
    input.value = value || "";
    $("prompt-accept").onclick = () => dialog.close("ok");
    input.onkeydown = (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        dialog.close("ok");
      }
    };
    dialog.onclose = () => resolve(dialog.returnValue === "ok" ? input.value.trim() : null);
    dialog.returnValue = "";
    dialog.showModal();
    input.focus();
    input.select();
  });
}

function shortSource(name) {
  return (name || "").replace(/\.(log|txt)$/i, "");
}

/* ── Investigations ──────────────────────────────────────────────────── */

async function invLoadList(selectId) {
  const data = await invApi("list", {});
  const select = $("inv-select");
  select.innerHTML = "";
  if (!data.items.length) {
    const option = el("option", null, "– noch keine Untersuchung –");
    option.value = "";
    select.append(option);
  }
  for (const item of data.items) {
    const option = el("option", null, `${item.name} · ${plural(item.sources, "Datei", "Dateien")} · ${formatBytes(item.size)}`);
    option.value = item.id;
    select.append(option);
  }
  const wanted = selectId || data.current || (data.items[0] && data.items[0].id) || "";
  select.value = wanted;
  inv.loaded = true;
  if (wanted && wanted !== data.current) {
    await invOpen(wanted);
  } else if (wanted) {
    inv.current = wanted;
    invSetOverview(await invApi("overview", {}));
    await invSearch(0);
  } else {
    inv.current = null;
    invSetOverview(null);
  }
}

async function invOpen(id) {
  invResetView();
  inv.current = id;
  invSetOverview(await invApi("open", { id }));
  await invSearch(0);
}

function invResetView() {
  inv.anchors = [];
  inv.sources.clear();
  inv.etypes.clear();
  inv.selected.clear();
  inv.context = null;
  inv.result = null;
  inv.eventId = null;
  inv.entityId = null;
  inv.graph = null;
  inv.scan = null;
  invRenderScan();
  $("inv-query").value = "";
  $("inv-from").value = "";
  $("inv-to").value = "";
  invRenderAnchors();
  $("inv-side-event").innerHTML = '<p class="empty">Ein Ereignis in der Zeitleiste anklicken.</p>';
  $("inv-side-entity").innerHTML = '<p class="empty">Einen erkannten Wert anklicken.</p>';
  $("inv-graph").innerHTML = '<p class="empty">Einen Wert wählen, um seine Beziehungen zu sehen.</p>';
  $("inv-graph-info").innerHTML = "";
}

function invSetOverview(overview) {
  inv.overview = overview;
  const has = Boolean(overview);
  const filled = has && overview.sources.length > 0;
  $("inv-intro").hidden = filled;
  $("inv-overview").hidden = !filled;
  $("inv-search-card").hidden = !filled;
  $("inv-main").hidden = !filled;
  for (const action of ["inv-add-files", "inv-add-folder", "inv-delete"]) {
    document.querySelector(`[data-action="${action}"]`).disabled = !has;
  }
  if (!has) {
    $("inv-note").textContent = "Lege eine Untersuchung an, zum Beispiel pro Ticket.";
    return;
  }
  if (!filled && !overview.importJob) $("inv-note").textContent = "Jetzt Logdateien oder einen Ordner hinzufügen.";
  invRenderSummary();
  invRenderSources();
  invRenderFilters();
  if (overview.importJob && inv.job !== overview.importJob) {
    invFollowImport(overview.importJob).catch((error) => setStatus(error.message, "error"));
  }
  invLockForImport(Boolean(inv.job));
}

function invRenderSummary() {
  const o = inv.overview;
  const holder = $("inv-summary");
  holder.innerHTML = "";
  const stat = (value, label, title) => {
    const node = el("span", "stat");
    node.append(el("b", null, value), el("span", null, label));
    if (title) node.title = title;
    holder.append(node);
  };
  stat(o.sources.length.toLocaleString("de-DE"), o.sources.length === 1 ? "Datei" : "Dateien");
  stat(o.counts.lines.toLocaleString("de-DE"), "Zeilen");
  stat(o.counts.events.toLocaleString("de-DE"), "Ereignisse");
  stat(o.counts.entities.toLocaleString("de-DE"), "erkannte Werte");
  if (o.firstMs) stat(`${localStamp(o.firstMs)} – ${localStamp(o.lastMs)}`, "", "Zeitraum, in der Zeitzone dieses Rechners");
  const naive =
    o.naiveFlag === "inferred"
      ? `Zeilen ohne Zeitzone: ${formatOffset(o.naiveOffset)} (aus anderen Logs übernommen)`
      : o.naiveFlag === "source"
        ? `Zeilen ohne Zeitzone: ${formatOffset(o.naiveOffset)} (fest eingestellt)`
        : "Zeilen ohne Zeitzone: Zeitzone dieses Rechners";
  stat("", naive);
  if (!o.fts) stat("", "Volltextindex nicht verfügbar, Suche langsamer", "Diese Python-Version bringt SQLite ohne FTS5 mit.");
}

function invRenderSources() {
  const o = inv.overview;
  const tz = o.defaultTz || "auto";
  $("inv-default-tz").value = tz.startsWith("fixed:") ? "fixed" : tz;
  $("inv-default-offset").value = tz.startsWith("fixed:") ? formatOffset(Number(tz.slice(6))) : "";
  $("inv-default-offset").hidden = !tz.startsWith("fixed:");

  const table = $("inv-sources");
  table.innerHTML = "";
  const head = el("thead");
  const headRow = el("tr");
  for (const title of ["Datei", "Format", "Zeilen", "Ereignisse", "Zeitraum", "Zeitangaben", "Zeitzone", "Uhr ± s", ""]) {
    headRow.append(el("th", null, title));
  }
  head.append(headRow);
  const body = el("tbody");
  for (const source of o.sources) {
    const row = el("tr");
    const name = el("td", "name", source.name);
    name.title = source.path;
    const format = el("td", null, source.parser_label);
    format.title = `Kodierung: ${source.encoding}`;
    const span = el("td", null, source.first_ms ? `${localStamp(source.first_ms)} – ${localStamp(source.last_ms, false)}` : "–");
    const flags = el("td", "inv-flags");
    const counts = source.timeFlags || {};
    const parts = [];
    const missing = (counts.none || 0) + (counts.ambiguous || 0) + (counts.invalid || 0);
    if (missing) parts.push([`${missing} ohne`, true]);
    if (counts.inherited) parts.push([`${counts.inherited} übernommen`, false]);
    if (counts.exact) parts.push([`${counts.exact} mit Zone`, false]);
    if (!parts.length) parts.push(["vollständig", false]);
    parts.forEach(([text, warn], index) => {
      if (index) flags.append(", ");
      flags.append(el("span", warn ? "warn" : null, text));
    });
    flags.title = Object.entries(counts)
      .map(([flag, count]) => `${count} × ${(TIME_FLAGS[flag] || { title: flag }).title}`)
      .join("\n");

    const zoneCell = el("td");
    const mode = el("select");
    mode.setAttribute("aria-label", `Zeitzone für ${source.name}`);
    for (const [value, label] of [["auto", source.detected_offset !== null && source.detected_offset !== undefined ? `erkannt ${formatOffset(source.detected_offset)}` : "wie Standard"], ["fixed", "fest"]]) {
      const option = el("option", null, label);
      option.value = value;
      mode.append(option);
    }
    mode.value = source.tz_mode === "fixed" ? "fixed" : "auto";
    const offset = el("input", "inv-offset");
    offset.type = "text";
    offset.placeholder = "+02:00";
    offset.value = source.tz_mode === "fixed" ? formatOffset(source.tz_offset) : "";
    offset.hidden = mode.value !== "fixed";
    offset.setAttribute("aria-label", "Abweichung von UTC");
    mode.onchange = () => {
      offset.hidden = mode.value !== "fixed";
    };
    zoneCell.append(mode, " ", offset);

    const skewCell = el("td");
    const skew = el("input", "inv-skew");
    skew.type = "text";
    skew.value = source.skew_ms ? String(source.skew_ms / 1000) : "";
    skew.placeholder = "0";
    skew.title = "Uhr dieses Systems korrigieren: positive Sekunden verschieben seine Ereignisse nach später.";
    skew.setAttribute("aria-label", "Uhrkorrektur in Sekunden");
    skewCell.append(skew);

    const actionsCell = el("td");
    const apply = el("button", "btn btn-quiet", "Übernehmen");
    apply.type = "button";
    apply.onclick = () =>
      invApplySourceTime(source, mode.value, offset.value, skew.value).catch((error) => setStatus(error.message, "error"));
    const remove = el("button", "btn btn-danger-quiet", "Entfernen");
    remove.type = "button";
    remove.onclick = () => invRemoveSource(source).catch((error) => setStatus(error.message, "error"));
    actionsCell.append(apply, remove);

    row.append(
      name,
      format,
      el("td", "num", source.lines.toLocaleString("de-DE")),
      el("td", "num", source.events.toLocaleString("de-DE")),
      span,
      flags,
      zoneCell,
      skewCell,
      actionsCell
    );
    body.append(row);
  }
  table.append(head, body);
}

async function invApplySourceTime(source, mode, offsetText, skewText) {
  let offset = null;
  if (mode === "fixed") {
    offset = parseOffset(offsetText);
    if (offset === null) throw new Error("Zeitzone bitte als Abweichung von UTC angeben, zum Beispiel +02:00.");
  }
  const skew = Number(String(skewText || "0").replace(",", "."));
  if (!Number.isFinite(skew)) throw new Error("Uhrkorrektur bitte in Sekunden angeben, zum Beispiel -3,5.");
  await invTimeJob({ sourceId: source.id, mode, offset, skewSeconds: skew });
  setStatus(`Zeit für ${source.name} neu berechnet`, null);
  await invSearch(inv.offset);
}

// Recomputing times can take a while on a large investigation: it runs as a job.
async function invTimeJob(body) {
  setStatus("Zeiten werden neu berechnet …", "busy");
  const started = await invApi("time", body);
  const job = await runJob(started.job, { progressEl: $("inv-progress"), noteEl: $("inv-note") });
  if (job.status === "error") throw new Error(job.error || "Die Zeiten konnten nicht neu berechnet werden.");
  invSetOverview(job.result.overview);
  $("inv-note").textContent = "";
}

async function invRemoveSource(source) {
  const ok = await askConfirm(
    "Datei aus der Untersuchung entfernen",
    `${source.name} wird aus dem Index entfernt. Die Datei selbst bleibt unverändert.`,
    "Entfernen"
  );
  if (!ok) return;
  inv.sources.delete(source.id);
  invSetOverview(await invApi("source/remove", { sourceId: source.id }));
  await invSearch(0);
}

/* ── Import: check first, then priority and background ─────────────────── */

const GB = 1024 * 1024 * 1024;
// Read throughput when the investigation has not measured one yet: deliberately low.
const DEFAULT_RATE = 1024 * 1024;

async function invScan(paths) {
  if (!paths || !paths.length) return;
  setStatus("Dateien werden geprüft …", "busy");
  const started = await invApi("scan", { paths });
  inv.job = started.job;
  let job;
  try {
    job = await runJob(started.job, {
      progressEl: $("inv-progress"),
      noteEl: $("inv-note"),
      cancelEl: document.querySelector('[data-action="inv-cancel"]'),
    });
  } finally {
    inv.job = null;
  }
  if (job.status === "error") throw new Error(job.error || "Die Dateien konnten nicht geprüft werden.");
  if (job.status === "cancelled") {
    setStatus("Prüfung abgebrochen", null);
    return;
  }
  inv.scan = invPrepareScan(job.result.scan);
  invRenderScan();
  $("inv-note").textContent = "";
  setStatus("Auswahl prüfen, dann Import starten", null);
}

function invPrepareScan(scan) {
  const fresh = scan.files.filter((file) => !file.imported && !file.error);
  const size = fresh.reduce((sum, file) => sum + file.size, 0);
  // Small collections go in at once; for large ones the choice is the user's.
  const choice = {};
  for (const group of scan.groups) choice[group.kind] = size <= GB ? "first" : "background";
  const times = scan.files.filter((file) => file.firstMs !== null && file.firstMs !== undefined);
  const low = times.length ? Math.min(...times.map((file) => file.firstMs)) : null;
  const high = times.length ? Math.max(...times.map((file) => file.lastMs ?? file.firstMs)) : null;
  return { ...scan, choice, open: new Set(), low, high, large: size > GB };
}

// Times from the scan are wall-clock times as the logs wrote them, kept as if UTC.
function wallInput(ms) {
  if (ms === null || ms === undefined) return "";
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}T${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
}

function wallFromInput(value) {
  const match = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d)(?::(\d\d))?/.exec(value || "");
  return match ? Date.UTC(+match[1], +match[2] - 1, +match[3], +match[4], +match[5], +(match[6] || 0)) : null;
}

function wallStamp(ms, withDate = true) {
  if (ms === null || ms === undefined) return "";
  const text = wallInput(ms).replace("T", " ");
  return withDate ? text : text.slice(11);
}

function invInWindow(file) {
  if (!$("inv-scan-window").checked) return true;
  const from = wallFromInput($("inv-scan-from").value);
  const to = wallFromInput($("inv-scan-to").value);
  if (file.firstMs === null || file.firstMs === undefined) return true; // no time to judge by
  const last = file.lastMs ?? file.firstMs;
  return (from === null || last >= from) && (to === null || file.firstMs <= to + 999);
}

// Which files go first, which into the background, which not at all.
function invPlan() {
  const scan = inv.scan;
  const plan = { first: [], background: [], skipped: [], known: [] };
  const outside = $("inv-scan-outside").value;
  for (const file of scan.files) {
    if (file.error) continue;
    if (file.imported) {
      plan.known.push(file);
      continue;
    }
    const choice = scan.choice[file.kind];
    if (choice === "skip") plan.skipped.push(file);
    else if (!invInWindow(file)) (outside === "background" ? plan.background : plan.skipped).push(file);
    else if (choice === "first") plan.first.push(file);
    else plan.background.push(file);
  }
  return plan;
}

function duration(seconds) {
  if (!Number.isFinite(seconds)) return "";
  if (seconds < 60) return "unter 1 min";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `ca. ${minutes} min`;
  const hours = Math.floor(minutes / 60);
  return `ca. ${hours} h ${pad2(minutes % 60)} min`;
}

function invRenderScan() {
  const scan = inv.scan;
  $("inv-scan").hidden = !scan;
  if (!scan) return;
  const total = scan.files.reduce((sum, file) => sum + (file.size || 0), 0);
  $("inv-scan-total").textContent =
    `${plural(scan.files.length, "Datei", "Dateien")} · ${formatBytes(total)}` +
    (scan.low !== null ? ` · ${wallStamp(scan.low)} – ${wallStamp(scan.high)}` : "");
  $("inv-scan-hint").textContent = scan.large
    ? "Eine große Sammlung. Logarten, die für den Fall zählen, auf „Zuerst“ stellen: Sie sind durchsuchbar, sobald sie eingelesen sind, der Rest folgt im Hintergrund. Mit dem Zeitraum lassen sich Tage auslassen, die nichts zur Sache tun."
    : "Logarten auf „Zuerst“ werden vorweg eingelesen; „Hintergrund“ folgt danach, „Nicht“ wird ausgelassen.";
  if (!$("inv-scan-from").value && scan.low !== null) {
    $("inv-scan-from").value = wallInput(scan.low);
    $("inv-scan-to").value = wallInput(scan.high);
  }
  const table = $("inv-scan-table");
  table.innerHTML = "";
  const head = el("thead");
  const headRow = el("tr");
  for (const title of ["Logart", "Dateien", "Größe", "Zeitraum laut Log", "Format", "Import"]) headRow.append(el("th", null, title));
  head.append(headRow);
  const body = el("tbody");
  for (const group of scan.groups) {
    const files = scan.files.filter((file) => file.kind === group.kind);
    const inside = files.filter((file) => !file.imported && !file.error && !file.within && invInWindow(file));
    const row = el("tr");
    const name = el("td", "name", group.kind);
    const count = el("td", "num");
    count.append(`${inside.length}${inside.length !== files.length ? " von " + files.length : ""} `);
    const toggle = el("button", "link", scan.open.has(group.kind) ? "ausblenden" : "zeigen");
    toggle.type = "button";
    toggle.onclick = () => {
      if (scan.open.has(group.kind)) scan.open.delete(group.kind);
      else scan.open.add(group.kind);
      invRenderScan();
    };
    count.append(toggle);
    const size = el("td", "num", formatBytes(inside.reduce((sum, file) => sum + file.size, 0)));
    size.title = `alle Dateien dieser Logart: ${formatBytes(group.size)}`;
    const range = el("td", null, group.firstMs !== null ? `${wallStamp(group.firstMs)} – ${wallStamp(group.lastMs)}` : "–");
    const formats = el("td", null, group.formats.join(", "));
    const choiceCell = el("td");
    const choice = el("span", "choice");
    choice.setAttribute("role", "group");
    choice.setAttribute("aria-label", `Import von ${group.kind}`);
    for (const [value, label] of [["first", "Zuerst"], ["background", "Hintergrund"], ["skip", "Nicht"]]) {
      const button = el("button", null, label);
      button.type = "button";
      button.dataset.choice = value;
      button.setAttribute("aria-pressed", String(scan.choice[group.kind] === value));
      button.onclick = () => {
        scan.choice[group.kind] = value;
        invRenderScan();
      };
      choice.append(button);
    }
    choiceCell.append(choice);
    if (group.imported) {
      choiceCell.append(el("span", "hint", ` ${group.imported} schon im Index`));
    }
    if (group.within) {
      choiceCell.append(el("span", "hint", ` ${plural(group.within, "frühere Fassung", "frühere Fassungen")}`));
    }
    row.append(name, count, size, range, formats, choiceCell);
    body.append(row);
    if (scan.open.has(group.kind)) {
      const filesRow = el("tr", "files");
      const cell = el("td");
      cell.colSpan = 6;
      const list = el("ul");
      for (const file of files.slice(0, 300)) {
        const item = el("li", invInWindow(file) ? null : "out");
        const label = el("span", "name", file.name);
        label.title = file.path;
        item.append(label, el("span", null, formatBytes(file.size)),
          el("span", null, file.error ? "nicht lesbar" : file.firstMs !== null ? `${wallStamp(file.firstMs)} – ${wallStamp(file.lastMs, false)}` : "ohne erkennbare Zeit"));
        if (file.imported) item.append(el("span", "hint", "schon im Index"));
        if (file.within) item.append(el("span", "hint", `frühere Fassung von ${file.within}, wird nicht eigens eingelesen`));
        if (file.replaces) item.append(el("span", "hint", `setzt ${file.replaces.join(", ")} fort und ersetzt den eingelesenen Stand`));
        list.append(item);
      }
      if (files.length > 300) list.append(el("li", "hint", `… und ${files.length - 300} weitere`));
      cell.append(list);
      filesRow.append(cell);
      body.append(filesRow);
    }
  }
  table.append(head, body);
  invRenderPlanSummary();
}

function invRenderPlanSummary() {
  const plan = invPlan();
  const rate = (inv.overview && inv.overview.rate) || DEFAULT_RATE;
  const holder = $("inv-scan-summary");
  holder.innerHTML = "";
  const part = (label, all, withTime) => {
    // Earlier copies of a growing log go along for the check but are not read.
    const files = withTime ? all.filter((file) => !file.within) : all;
    const size = files.reduce((sum, file) => sum + file.size, 0);
    const node = el("span");
    node.append(el("b", null, label), ` ${plural(files.length, "Datei", "Dateien")}, ${formatBytes(size)}`);
    if (withTime && files.length) node.append(` (${duration(size / rate)})`);
    return node;
  };
  holder.append(part("Zuerst:", plan.first, true), " · ", part("Hintergrund:", plan.background, true), " · ",
    part("Ausgelassen:", plan.skipped, false));
  if (plan.known.length) holder.append(` · ${plural(plan.known.length, "Datei", "Dateien")} schon im Index`);
  const within = [...plan.first, ...plan.background].filter((file) => file.within);
  if (within.length) holder.append(` · ${plural(within.length, "frühere Fassung", "frühere Fassungen")} fortgeschriebener Logs, nur die längste wird eingelesen`);
  const replacing = [...plan.first, ...plan.background].filter((file) => file.replaces);
  if (replacing.length) holder.append(` · ${plural(replacing.length, "Datei ersetzt", "Dateien ersetzen")} einen eingelesenen kürzeren Stand`);
  holder.title = inv.overview && inv.overview.rate
    ? `Geschätzt mit der zuletzt gemessenen Geschwindigkeit von ${formatBytes(rate)}/s.`
    : "Grobe Schätzung; nach dem ersten Import wird die gemessene Geschwindigkeit genommen.";
  document.querySelector('[data-action="inv-import-start"]').disabled = !plan.first.length && !plan.background.length;
}

async function invStartImport() {
  const plan = invPlan();
  if (!plan.first.length && !plan.background.length) throw new Error("Nichts zu importieren.");
  const started = await invApi("import", {
    priority: plan.first.map((file) => file.path),
    background: plan.background.map((file) => file.path),
  });
  inv.scan = null;
  invRenderScan();
  await invFollowImport(started.job);
}

const PHASES = { prepare: "Vorbereitung", priority: "Zuerst", background: "Hintergrund", done: "Abschluss" };

// Follows an import, also one started before the page was opened. Priority
// files make the investigation usable when they are done; background files
// show up one by one.
async function invFollowImport(jobId) {
  if (inv.job === jobId) return;
  inv.job = jobId;
  inv.readyShown = false;
  invLockForImport(true);
  $("inv-run").hidden = false;
  let lastRefresh = Date.now();
  try {
    const job = await runJob(jobId, {
      progressEl: $("inv-progress"),
      noteEl: null,
      cancelEl: document.querySelector('[data-action="inv-cancel"]'),
      onProgress: (state) => {
        invShowImport(state);
        const detail = state.detail || {};
        if (detail.ready && !inv.readyShown) {
          inv.readyShown = true;
          setStatus("Priorisierte Logs sind durchsuchbar", null);
          invRefreshAfterImport(true).catch(() => {});
        } else if (Date.now() - lastRefresh > 20000 && (detail.files || 0) > 0) {
          lastRefresh = Date.now();
          invRefreshAfterImport(false).catch(() => {});
        }
      },
    });
    if (job.status === "error") throw new Error(job.error || "Import fehlgeschlagen");
    const report = job.result ? job.result.report : null;
    if (job.result && job.result.overview) invSetOverview(Object.assign(job.result.overview, { importJob: null }));
    if (report) {
      const parts = [plural(report.imported.length, "Datei eingelesen", "Dateien eingelesen")];
      if (report.duplicates.length) parts.push(plural(report.duplicates.length, "Dublette übersprungen", "Dubletten übersprungen"));
      if ((report.continued || []).length) parts.push(plural(report.continued.length, "frühere Fassung übersprungen", "frühere Fassungen übersprungen"));
      if ((report.replaced || []).length) parts.push(plural(report.replaced.length, "eingelesener Stand ersetzt", "eingelesene Stände ersetzt"));
      if (report.failed.length) parts.push(plural(report.failed.length, "Fehler", "Fehler"));
      $("inv-note").textContent = parts.join(", ") + (report.failed.length ? ": " + report.failed.map((item) => item.error).join("; ") : "");
    }
    setStatus(job.status === "cancelled" ? "Import abgebrochen; Eingelesenes bleibt" : "Import fertig", job.status === "cancelled" ? "error" : null);
    await invLoadListKeep();
    await invSearch(inv.offset);
  } finally {
    inv.job = null;
    $("inv-run").hidden = true;
    invLockForImport(false);
  }
}

function invShowImport(state) {
  const detail = state.detail || {};
  const phase = detail.phase || "prepare";
  $("inv-run-phase").textContent = PHASES[phase] || phase;
  $("inv-run-phase").className = "badge" + (phase === "background" ? " off" : phase === "priority" ? "" : " warn");
  const parts = [];
  if (detail.filesTotal) parts.push(`${detail.files} von ${plural(detail.filesTotal, "Datei", "Dateien")}`);
  if (detail.bytesTotal) parts.push(`${formatBytes(detail.bytes)} von ${formatBytes(detail.bytesTotal)}`);
  if (detail.elapsed > 5 && detail.bytes > 0 && detail.bytesTotal) {
    const rate = detail.bytes / detail.elapsed;
    parts.push(`Rest ${duration((detail.bytesTotal - detail.bytes) / rate)}`);
  }
  if (state.message) parts.push(state.message);
  $("inv-run-text").textContent = parts.join(" · ");
  $("inv-run-hint").textContent = detail.ready || phase === "background"
    ? "Durchsuchbar ist, was schon eingelesen ist; weitere Dateien kommen im Hintergrund dazu. Zeitzonen und Entfernen gehen wieder, wenn der Import fertig ist."
    : "Die priorisierten Logs werden eingelesen. Abbrechen behält, was vollständig eingelesen ist.";
}

async function invRefreshAfterImport(full) {
  const overview = await invApi("overview", {});
  if (full || !inv.overview || !inv.overview.sources.length) {
    invSetOverview(overview);
    await invSearch(0);
    return;
  }
  // Quietly: counts and files, without disturbing an open filter or the timeline.
  inv.overview = overview;
  invRenderSummary();
  if ($("inv-sources-details").open) invRenderSources();
  if (overview.version !== inv.searchedVersion) $("inv-refresh").hidden = false;
}

function invLockForImport(locked) {
  for (const action of ["inv-add-files", "inv-add-folder", "inv-delete", "inv-default-tz"]) {
    const button = document.querySelector(`[data-action="${action}"]`);
    if (button) button.disabled = locked || !inv.current;
  }
  for (const button of document.querySelectorAll("#inv-sources button")) button.disabled = locked;
}

// Refreshes the drop-down (file counts) without reopening the investigation.
async function invLoadListKeep() {
  const data = await invApi("list", {});
  const select = $("inv-select");
  for (const option of select.options) {
    const item = data.items.find((entry) => entry.id === option.value);
    if (item) option.textContent = `${item.name} · ${plural(item.sources, "Datei", "Dateien")} · ${formatBytes(item.size)}`;
  }
}

/* ── Filters ─────────────────────────────────────────────────────────── */

function invRenderFilters() {
  const o = inv.overview;
  const known = new Set(o.sources.map((source) => source.id));
  for (const id of [...inv.sources]) if (!known.has(id)) inv.sources.delete(id);
  invFillDropdown(
    $("inv-filter-sources"),
    o.sources.map((source) => ({ key: source.id, label: shortSource(source.name), meta: source.events.toLocaleString("de-DE"), title: source.path })),
    inv.sources,
    "Logs"
  );
  invFillDropdown(
    $("inv-filter-etypes"),
    o.etypes.map((item) => ({ key: item.etype, label: item.label, meta: item.count.toLocaleString("de-DE") })),
    inv.etypes,
    "Ereignisarten"
  );
}

function invFillDropdown(details, items, chosen, title) {
  const body = details.querySelector(".dropdown-body");
  body.innerHTML = "";
  const actions = el("div", "dropdown-actions");
  const all = el("button", "btn btn-quiet", "Alle");
  all.type = "button";
  all.onclick = () => {
    chosen.clear();
    invFillDropdown(details, items, chosen, title);
    invSearch(0);
  };
  actions.append(all);
  body.append(actions);
  for (const item of items) {
    const label = el("label", "check");
    const box = el("input");
    box.type = "checkbox";
    box.checked = chosen.has(item.key);
    box.onchange = () => {
      if (box.checked) chosen.add(item.key);
      else chosen.delete(item.key);
      invSummary(details, chosen, items.length, title);
      invSearch(0);
    };
    label.append(box, el("span", null, item.label), el("span", "meta", item.meta));
    if (item.title) label.title = item.title;
    body.append(label);
  }
  invSummary(details, chosen, items.length, title);
}

function invSummary(details, chosen, total, title) {
  details.querySelector("summary").textContent = chosen.size ? `${title}: ${chosen.size} von ${total}` : `${title}: alle`;
}

function invLevels() {
  return [...document.querySelectorAll("#inv-levels [data-level]")].filter((box) => box.checked).map((box) => Number(box.dataset.level));
}

function invPayload(offset) {
  const from = $("inv-from").value ? new Date($("inv-from").value).getTime() : null;
  const to = $("inv-to").value ? new Date($("inv-to").value).getTime() + 999 : null;
  return {
    query: $("inv-query").value.trim(),
    entities: inv.anchors.map((item) => item.id),
    sources: [...inv.sources],
    etypes: [...inv.etypes],
    minSeverity: $("inv-details").checked ? 0 : 1,
    from: Number.isFinite(from) ? from : null,
    to: Number.isFinite(to) ? to : null,
    levels: invLevels(),
    temporalSeconds: Number($("inv-temporal").value || 0),
    limit: inv.limit,
    offset,
  };
}

/* ── Search and timeline ─────────────────────────────────────────────── */

async function invSearch(offset = 0) {
  if (!inv.overview || !inv.overview.sources.length) return;
  inv.context = null;
  inv.offset = offset;
  const seq = ++inv.searchSeq;
  const payload = invPayload(offset);
  $("inv-result-note").textContent = "Suche läuft …";
  let result;
  try {
    result = await invApi("search", payload);
  } catch (error) {
    $("inv-result-note").textContent = "";
    throw error;
  }
  if (seq !== inv.searchSeq) return;
  inv.result = result;
  inv.searchedVersion = inv.overview ? inv.overview.version : 0;
  $("inv-refresh").hidden = true;
  if (result.mode === "trace" && !inv.anchors.length && result.anchors.length) {
    // Typed text was a known value: show it as the searched entity.
    inv.anchors = result.anchors;
    $("inv-query").value = "";
    invRenderAnchors();
  }
  invRenderTimeline();
}

function invRenderAnchors() {
  const list = $("inv-anchors");
  list.innerHTML = "";
  for (const item of inv.anchors) {
    const li = el("li", "anchor");
    li.append(entityChip(item, (entity) => invOpenEntity(entity.id)));
    const remove = el("button", null, "×");
    remove.type = "button";
    remove.title = "Nicht mehr danach suchen";
    remove.onclick = () => {
      inv.anchors = inv.anchors.filter((entry) => entry.id !== item.id);
      invRenderAnchors();
      invSearch(0).catch((error) => setStatus(error.message, "error"));
    };
    li.append(remove);
    list.append(li);
  }
  $("inv-levels").hidden = !inv.anchors.length;
}

function invRenderTimeline() {
  const result = inv.result;
  const rowsHolder = $("inv-rows");
  const banner = $("inv-banner");
  banner.hidden = true;
  banner.className = "inv-banner";
  const titles = { trace: "Spur", text: "Treffer", all: "Zeitleiste" };
  $("inv-result-title").textContent = titles[result.mode] || "Zeitleiste";
  const notes = [`${result.total > 100000 ? "über 100.000" : result.total.toLocaleString("de-DE")} Ereignisse`];
  if (result.levels) {
    notes.push(Object.entries(result.levels).map(([label, count]) => `${count.toLocaleString("de-DE")} ${label}`).join(" · "));
  }
  $("inv-result-note").textContent = notes.join(" — ");
  if (result.truncated) {
    banner.hidden = false;
    banner.classList.add("warn");
    banner.textContent = "Die Spur ist sehr groß und wurde begrenzt. Einen genaueren Wert oder einen Zeitraum wählen.";
  } else if (result.mode === "trace" && result.levels && invLevels().includes(3)) {
    banner.hidden = false;
    banner.textContent = "„Möglich“ heißt: Es gibt einen Hinweis, aber keinen Beleg. Zeitliche Nähe allein beweist keinen Zusammenhang.";
  }
  invRenderHistogram(result.histogram, result.mode === "trace");
  rowsHolder.innerHTML = "";
  invFillRows(result.rows);
  $("inv-rows-empty").hidden = result.rows.length > 0;
  $("inv-rows-empty").textContent =
    result.mode === "all" ? "Keine Ereignisse in diesen Filtern. Detailzeilen einblenden oder Filter zurücksetzen." : "Nichts gefunden. Detailzeilen einblenden, Filter lockern oder einen anderen Begriff versuchen.";
  const last = result.offset + result.rows.length;
  $("inv-page-note").textContent = result.rows.length ? `${(result.offset + 1).toLocaleString("de-DE")}–${last.toLocaleString("de-DE")} von ${result.total > 100000 ? "über 100.000" : result.total.toLocaleString("de-DE")}` : "";
  document.querySelector('[data-action="inv-prev"]').disabled = result.offset <= 0;
  document.querySelector('[data-action="inv-next"]').disabled = last >= result.total;
  invUpdateExportButton();
}

function invFillRows(rows) {
  const holder = $("inv-rows");
  let day = null;
  for (const row of rows) {
    const rowDay = row.time ? row.time.slice(0, 10) : "ohne Zeitangabe";
    if (rowDay !== day) {
      day = rowDay;
      holder.append(el("div", "inv-day", row.time ? `${rowDay} (${row.offset !== null ? "UTC" + formatOffset(row.offset) : "Zone unbekannt"})` : rowDay));
    }
    holder.append(invRow(row));
  }
}

function invRow(row) {
  const item = el("div", `inv-row sev-${row.severity}`);
  item.setAttribute("role", "listitem");
  item.tabIndex = 0;
  item.dataset.id = row.id;
  if (row.id === inv.eventId) item.setAttribute("aria-current", "true");
  const box = el("input");
  box.type = "checkbox";
  box.checked = inv.selected.has(row.id);
  box.title = "Für den Export wählen";
  box.setAttribute("aria-label", "Für den Export wählen");
  box.onclick = (event) => event.stopPropagation();
  box.onchange = () => {
    if (box.checked) inv.selected.add(row.id);
    else inv.selected.delete(row.id);
    invUpdateExportButton();
  };
  const flag = TIME_FLAGS[row.timeFlag] || TIME_FLAGS.none;
  const time = el("span", "time", row.time ? row.time.slice(11) : "—");
  time.title = row.time ? `${row.time} UTC${formatOffset(row.offset)}` : "ohne Zeitangabe";
  const tflag = el("span", "tflag" + (flag.warn ? " warn" : ""), flag.mark);
  tflag.title = flag.title;
  const src = el("span", "src", row.sourceKind || shortSource(row.source));
  src.title = `${row.source}, Zeile ${row.line}${row.lineEnd > row.line ? "–" + row.lineEnd : ""}`;
  const level = row.level ? levelBadge(row.level) : el("span", "lvl lvl-0", SEVERITIES[row.severity] || "");
  const body = el("div", "body");
  const message = el("div", "msg", (row.summary || row.text) + (row.lines > 1 ? `  (+${row.lines - 1} Zeilen)` : ""));
  message.title = row.text;
  const what = el("div", "what");
  what.append(el("span", null, row.etypeLabel));
  if (row.basis) {
    const basis = el("span", "basis", row.basis);
    what.append(basis);
  }
  // The session or request a row belongs to is the same on every row of it.
  for (const entity of row.entities.filter((item) => item.role !== "context").slice(0, 5)) {
    what.append(entityChip(entity, (chosen) => invOpenEntity(chosen.id)));
  }
  body.append(message, what);
  item.append(box, time, tflag, src, level, body);
  item.onclick = () => invSelectEvent(row.id).catch((error) => setStatus(error.message, "error"));
  item.onkeydown = (event) => {
    if (event.key === "Enter") item.click();
    if (event.key === "ArrowDown" && item.nextElementSibling) {
      event.preventDefault();
      const next = item.nextElementSibling.classList.contains("inv-row") ? item.nextElementSibling : item.nextElementSibling.nextElementSibling;
      if (next) next.focus();
    }
    if (event.key === "ArrowUp" && item.previousElementSibling) {
      event.preventDefault();
      const previous = item.previousElementSibling.classList.contains("inv-row") ? item.previousElementSibling : item.previousElementSibling.previousElementSibling;
      if (previous) previous.focus();
    }
  };
  return item;
}

function invRenderHistogram(histogram, traced) {
  const holder = $("inv-histogram");
  holder.innerHTML = "";
  if (!histogram || !histogram.counts.length) return;
  const ns = "http://www.w3.org/2000/svg";
  const width = 1000;
  const height = 48;
  const plot = 48;
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("role", "img");
  const totals = histogram.counts.map((bucket) => bucket.reduce((sum, value) => sum + value, 0));
  const max = Math.max(1, ...totals);
  const step = width / histogram.counts.length;
  const colors = traced ? [null, "var(--green)", "var(--blue)", "var(--orange)"] : ["var(--blue)"];
  histogram.counts.forEach((bucket, index) => {
    let y = plot;
    const parts = traced ? [1, 2, 3] : [0];
    for (const level of parts) {
      const value = bucket[level];
      if (!value) continue;
      const h = Math.max(1.5, (value / max) * (plot - 4));
      y -= h;
      const rect = document.createElementNS(ns, "rect");
      rect.setAttribute("class", "bar");
      rect.setAttribute("x", String(index * step + 0.5));
      rect.setAttribute("width", String(Math.max(1, step - 1)));
      rect.setAttribute("y", String(y));
      rect.setAttribute("height", String(h));
      rect.setAttribute("fill", colors[level] || "var(--blue)");
      const start = histogram.from + index * histogram.bucketMs;
      const title = document.createElementNS(ns, "title");
      title.textContent = `${localStamp(start)} – ${localStamp(start + histogram.bucketMs, false)}: ${totals[index].toLocaleString("de-DE")} Ereignisse` +
        (traced ? ` (${bucket[1]} direkt, ${bucket[2]} stark, ${bucket[3]} möglich)` : "") + "\nKlicken: auf diesen Zeitraum eingrenzen";
      rect.append(title);
      rect.addEventListener("click", () => {
        $("inv-from").value = localInput(start);
        $("inv-to").value = localInput(start + histogram.bucketMs);
        invSearch(0).catch((error) => setStatus(error.message, "error"));
      });
      svg.append(rect);
    }
  });
  const end = histogram.from + histogram.counts.length * histogram.bucketMs;
  const scale = el("div", "axis");
  const legend = "Ortszeit dieses Rechners · Balken anklicken grenzt ein" + (histogram.approximate ? " · in Zehn-Minuten-Schritten" : "");
  scale.append(el("span", null, localStamp(histogram.from)), el("span", null, legend), el("span", null, localStamp(end)));
  holder.append(svg, scale);
}

async function invShowContext(eventId, label) {
  const data = await invApi("context", { id: eventId });
  inv.context = { eventId, label };
  $("inv-result-title").textContent = label || "Zusammenhang";
  $("inv-result-note").textContent = plural(data.rows.length, "Ereignis", "Ereignisse") + " in Logreihenfolge";
  const banner = $("inv-banner");
  banner.className = "inv-banner";
  banner.hidden = false;
  banner.innerHTML = "";
  const back = el("button", "btn", "‹ Zurück zur Suche");
  back.type = "button";
  back.onclick = () => invSearch(inv.offset).catch((error) => setStatus(error.message, "error"));
  banner.append(back, el("span", null, "Alle Zeilen dieser Sitzung, dieses Requests oder Verarbeitungsblocks, ungefiltert."));
  $("inv-histogram").innerHTML = "";
  $("inv-rows").innerHTML = "";
  invFillRows(data.rows);
  $("inv-rows-empty").hidden = data.rows.length > 0;
  $("inv-page-note").textContent = "";
  document.querySelector('[data-action="inv-prev"]').disabled = true;
  document.querySelector('[data-action="inv-next"]').disabled = true;
}

/* ── Event detail ────────────────────────────────────────────────────── */

function invSide(name) {
  for (const tab of document.querySelectorAll("#inv-side-tabs [data-side]")) {
    tab.setAttribute("aria-selected", String(tab.dataset.side === name));
  }
  $("inv-side-event").hidden = name !== "event";
  $("inv-side-entity").hidden = name !== "entity";
  $("inv-side-graph").hidden = name !== "graph";
}

async function invSelectEvent(id) {
  inv.eventId = id;
  for (const row of document.querySelectorAll("#inv-rows .inv-row")) {
    if (Number(row.dataset.id) === id) row.setAttribute("aria-current", "true");
    else row.removeAttribute("aria-current");
  }
  const data = await invApi("event", { id, anchors: inv.anchors.map((item) => item.id) });
  invRenderEvent(data);
  invSide("event");
}

function invRenderEvent(d) {
  const holder = $("inv-side-event");
  holder.innerHTML = "";
  const head = el("div", "inv-ent-head");
  const title = el("div");
  title.append(el("div", "value", d.time ? `${d.time} UTC${formatOffset(d.offset)}` : "ohne Zeitangabe"));
  title.append(el("div", "hint", `${d.etypeLabel} · ${SEVERITIES[d.severity] || ""}`));
  head.append(title);
  if (d.level) head.append(levelBadge(d.level));
  holder.append(head);

  const kv = el("dl", "kv");
  const add = (label, value) => {
    if (value === "" || value === null || value === undefined) return;
    kv.append(el("dt", null, label));
    const dd = el("dd");
    if (value instanceof Node) dd.append(value);
    else dd.textContent = value;
    kv.append(dd);
  };
  add("Datei", `${d.source}, Zeile ${d.line}${d.lineEnd > d.line ? "–" + d.lineEnd : ""}`);
  add("Pfad", d.path);
  add("Zeit", d.timeFlagLabel + (d.wall && d.timeFlag !== "exact" ? ` (im Log: ${d.wall})` : ""));
  if (d.basis) add("Warum in der Spur", d.basis);
  if (d.context) {
    const context = el("span");
    context.append(`${d.contextLabel || "Zusammenhang"} (${plural(d.contextSize || 0, "Ereignis", "Ereignisse")}) `);
    const show = el("button", "btn btn-quiet", "Alle zeigen");
    show.type = "button";
    show.onclick = () => invShowContext(d.id, d.contextLabel).catch((error) => setStatus(error.message, "error"));
    context.append(show);
    add("Gehört zu", context);
  }
  holder.append(kv);

  holder.append(el("h3", null, "Originalzeilen"));
  holder.append(invLinesWithMarks(d));

  if (d.entities.length) {
    holder.append(el("h3", null, "Erkannte Werte"));
    const list = el("div", "ent-list");
    for (const entity of d.entities) list.append(entityChip(entity, (chosen) => invOpenEntity(chosen.id)));
    holder.append(list);
    holder.append(el("p", "hint", "Wert anklicken: alle Vorkommen und Beziehungen. Unterpunktet: häufiger oder allgemeiner Wert, verknüpft nur eingeschränkt."));
  }
}

// The event's own lines with every recognized value marked; the lines around
// them show where in the file it stands.
function invLinesWithMarks(d) {
  const box = el("div", "inv-lines");
  const messageLines = d.text.split("\n");
  const starts = [];
  let position = 0;
  for (const line of messageLines) {
    starts.push(position);
    position += line.length + 1;
  }
  const byKey = new Map(d.entities.map((item) => [`${item.kind}\u0000${item.value}`, item]));
  let next = 0;
  for (const line of d.contextLines) {
    const row = el("div", line.own ? "own" : null);
    row.append(el("span", "no", String(line.line)));
    const text = el("span", "tx");
    let index = -1;
    if (line.own) {
      for (let probe = next; probe < messageLines.length; probe += 1) {
        if (messageLines[probe] === line.text) {
          index = probe;
          next = probe + 1;
          break;
        }
      }
    }
    if (index < 0) {
      text.textContent = line.text;
    } else {
      const lineStart = starts[index];
      const lineEnd = lineStart + line.text.length;
      const spans = d.spans
        .filter((span) => span.start >= lineStart && span.end <= lineEnd)
        .sort((a, b) => a.start - b.start || b.end - a.end);
      let cursor = lineStart;
      for (const span of spans) {
        if (span.start < cursor) continue;
        text.append(line.text.slice(cursor - lineStart, span.start - lineStart));
        const mark = el("mark", null, line.text.slice(span.start - lineStart, span.end - lineStart));
        const meta = kindOf(span.kind);
        mark.style.color = `var(--${meta.color})`;
        mark.style.background = `color-mix(in srgb, var(--${meta.color}) 14%, transparent)`;
        const entity = byKey.get(`${span.kind}\u0000${span.value}`);
        mark.title = meta.label + (entity ? " – anklicken für alle Vorkommen" : "");
        if (entity) mark.onclick = () => invOpenEntity(entity.id).catch((error) => setStatus(error.message, "error"));
        text.append(mark);
        cursor = span.end;
      }
      text.append(line.text.slice(cursor - lineStart));
    }
    row.append(text);
    box.append(row);
  }
  return box;
}

/* ── Entity explorer ─────────────────────────────────────────────────── */

async function invOpenEntity(id) {
  inv.entityId = id;
  invSide("entity");
  $("inv-side-entity").innerHTML = '<p class="empty">Wird geladen …</p>';
  const data = await invApi("entity", { id });
  invRenderEntity(data);
}

function invAddAnchor(entity, replace) {
  if (replace) inv.anchors = [];
  if (!inv.anchors.some((item) => item.id === entity.id)) inv.anchors.push(entity);
  $("inv-query").value = "";
  invRenderAnchors();
  return invSearch(0);
}

function invRenderEntity(d) {
  const holder = $("inv-side-entity");
  holder.innerHTML = "";
  const head = el("div", "inv-ent-head");
  const titleBox = el("div");
  titleBox.append(el("div", "hint", d.kindLabel), el("div", "value", d.display || d.value));
  head.append(titleBox);
  holder.append(head);

  const tags = el("div", "inv-tags");
  if (d.unique) tags.append(el("span", "tag good", "eindeutig: verknüpft direkt"));
  if (d.weak) tags.append(el("span", "tag", "beschreibend: nur durchsuchbar"));
  if (d.common) tags.append(el("span", "tag warn", "häufig: verknüpft nur in zeitlicher Nähe"));
  if (d.generic) tags.append(el("span", "tag warn", "allgemein: verknüpft nicht"));
  if (d.excluded) tags.append(el("span", "tag bad", "von dir ausgeschlossen"));
  if (d.included) tags.append(el("span", "tag good", "von dir freigegeben"));
  if (!["msgid", "queue", "session", "request", "email", "account", "device", "ipv4", "ipv6", "endpoint"].includes(d.kind) && !d.weak) {
    tags.append(el("span", "tag", "durchsuchbar, verknüpft nicht allein"));
  }
  holder.append(tags);

  const kv = el("dl", "kv");
  const add = (label, value) => {
    kv.append(el("dt", null, label), el("dd", null, value));
  };
  add("Vorkommen", `${d.events.toLocaleString("de-DE")} Ereignisse in ${plural(d.sources, "Log", "Logs")}, ${plural(d.groups, "Zusammenhang", "Zusammenhängen")}`);
  if (d.first) add("Zuerst", `${d.first} UTC`);
  if (d.last) add("Zuletzt", `${d.last} UTC`);
  const roles = Object.entries(d.roles || {}).filter(([role]) => role !== "context");
  if (roles.length) add("Rollen", roles.map(([role, count]) => `${role} ${count}×`).join(", "));
  if (d.levels) add("Spur", Object.entries(d.levels).map(([label, count]) => `${count.toLocaleString("de-DE")} ${label}`).join(" · "));
  holder.append(kv);

  const actions = el("div", "card-actions card-actions-start");
  const button = (label, handler, className) => {
    const node = el("button", className || "btn", label);
    node.type = "button";
    node.onclick = () => Promise.resolve(handler()).catch((error) => setStatus(error.message, "error"));
    actions.append(node);
    return node;
  };
  button("Spur zeigen", () => invAddAnchor(d, true), "btn btn-primary");
  if (inv.anchors.length && !inv.anchors.some((item) => item.id === d.id)) button("Zur Suche hinzufügen", () => invAddAnchor(d, false));
  button("Graph", () => invOpenGraph(d.id));
  if (!d.weak) {
    if ((d.common || d.generic) && !d.included) {
      button("Trotzdem verknüpfen", () => invFlag(d.id, "include"), "btn btn-quiet").title =
        "Diesen Wert wie einen seltenen behandeln, auch wenn er oft vorkommt";
    }
    if (!d.excluded) {
      button("Nie verknüpfen", () => invFlag(d.id, "exclude"), "btn btn-danger-quiet").title =
        "Dieser Wert verbindet nichts, zum Beispiel ein Proxy oder ein Testkonto";
    }
    if (d.excluded || d.included) button("Zurücksetzen", () => invFlag(d.id, "reset"), "btn btn-quiet");
  }
  holder.append(actions);

  if (d.bySource && d.bySource.length) {
    holder.append(el("h3", null, "In diesen Logs"));
    const table = el("table", "inv-mini");
    for (const source of d.bySource) {
      const row = el("tr", "click");
      row.title = "Nur dieses Log in der Spur zeigen";
      row.append(el("td", null, shortSource(source.source)), el("td", "num", source.events.toLocaleString("de-DE")),
        el("td", "num", source.first ? source.first.slice(5, 19) : ""), el("td", "num", source.last ? source.last.slice(5, 19) : ""));
      row.onclick = () => {
        inv.sources.clear();
        inv.sources.add(source.sourceId);
        invRenderFilters();
        invAddAnchor(d, true).catch((error) => setStatus(error.message, "error"));
      };
      table.append(row);
    }
    holder.append(table);
  }

  invEntityTable(holder, "Direkt verbunden", d.related, d.id, true,
    "Im selben Ereignis, derselben Sitzung, demselben Request oder Verarbeitungsblock.");
  invEntityTable(holder, "Mögliche Zusammenhänge", d.possible, d.id, false,
    "Werte aus Ereignissen der Stufe stark oder möglich: Hinweise, keine Belege.");
}

function invEntityTable(holder, title, items, anchorId, removable, hint) {
  if (!items || !items.length) return;
  holder.append(el("h3", null, title));
  holder.append(el("p", "hint", hint));
  const table = el("table", "inv-mini");
  for (const item of items) {
    const row = el("tr", "click");
    const cell = el("td");
    cell.append(entityChip(item));
    row.append(cell, el("td", "num", `${item.shared}×`));
    const last = el("td", "num");
    if (removable) {
      const x = el("button", "x", "×");
      x.type = "button";
      x.title = "Diese Verknüpfung ausschließen: die beiden Werte gelten nicht mehr als verbunden";
      x.setAttribute("aria-label", "Verknüpfung ausschließen");
      x.onclick = (event) => {
        event.stopPropagation();
        invExcludeLink(anchorId, item.id).catch((error) => setStatus(error.message, "error"));
      };
      last.append(x);
    }
    row.append(last);
    row.onclick = () => invOpenEntity(item.id).catch((error) => setStatus(error.message, "error"));
    table.append(row);
  }
  holder.append(table);
}

async function invFlag(id, action) {
  await invApi("flag", { id, action });
  await invOpenEntity(id);
  if (inv.anchors.length) await invSearch(inv.offset);
}

async function invExcludeLink(a, b) {
  await invApi("link", { a, b });
  setStatus("Verknüpfung ausgeschlossen", null);
  if (inv.entityId) await invOpenEntity(inv.entityId);
  if (inv.anchors.length) await invSearch(inv.offset);
  if (inv.graph && !$("inv-side-graph").hidden) await invOpenGraph(inv.graph.anchor);
}

/* ── Relationship graph ──────────────────────────────────────────────── */

function invRenderGraphKinds() {
  const holder = $("inv-graph-kinds");
  holder.innerHTML = "";
  for (const kind of GRAPH_KINDS) {
    const label = el("label", "check check-inline");
    const box = el("input");
    box.type = "checkbox";
    box.checked = inv.graphKinds.has(kind);
    box.onchange = () => {
      if (box.checked) inv.graphKinds.add(kind);
      else inv.graphKinds.delete(kind);
      if (inv.graph) invOpenGraph(inv.graph.anchor).catch((error) => setStatus(error.message, "error"));
    };
    label.append(box, kindOf(kind).label);
    holder.append(label);
  }
}

async function invOpenGraph(id) {
  invSide("graph");
  invRenderGraphKinds();
  $("inv-graph-info").innerHTML = "";
  const data = await invApi("graph", { id, kinds: [...inv.graphKinds] });
  inv.graph = data;
  invDrawGraph(data);
}

function invLayout(nodes, edges, anchor) {
  const pos = new Map();
  const count = nodes.length;
  nodes.forEach((node, index) => {
    const angle = (2 * Math.PI * index) / Math.max(1, count);
    const radius = node.id === anchor ? 0 : node.unique ? 140 : 230;
    pos.set(node.id, { x: radius * Math.cos(angle), y: radius * Math.sin(angle), vx: 0, vy: 0 });
  });
  const list = nodes.map((node) => pos.get(node.id));
  const rounds = 320;
  for (let round = 0; round < rounds; round += 1) {
    const heat = 1 - round / rounds;
    for (let i = 0; i < list.length; i += 1) {
      for (let j = i + 1; j < list.length; j += 1) {
        const a = list[i];
        const b = list[j];
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 1) {
          dx = Math.random() - 0.5;
          dy = Math.random() - 0.5;
          d2 = 1;
        }
        const force = 12000 / d2;
        const d = Math.sqrt(d2);
        a.vx += (dx / d) * force;
        a.vy += (dy / d) * force;
        b.vx -= (dx / d) * force;
        b.vy -= (dy / d) * force;
      }
    }
    for (const edge of edges) {
      const a = pos.get(edge.a);
      const b = pos.get(edge.b);
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const d = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const force = (d - 120) * 0.04;
      a.vx += (dx / d) * force;
      a.vy += (dy / d) * force;
      b.vx -= (dx / d) * force;
      b.vy -= (dy / d) * force;
    }
    for (const node of nodes) {
      const p = pos.get(node.id);
      if (node.id === anchor) {
        p.x = 0;
        p.y = 0;
        p.vx = 0;
        p.vy = 0;
        continue;
      }
      p.vx -= p.x * 0.012;
      p.vy -= p.y * 0.012;
      const speed = Math.sqrt(p.vx * p.vx + p.vy * p.vy);
      const limit = 4 + 26 * heat;
      if (speed > limit) {
        p.vx = (p.vx / speed) * limit;
        p.vy = (p.vy / speed) * limit;
      }
      p.x += p.vx;
      p.y += p.vy;
      p.vx *= 0.6;
      p.vy *= 0.6;
    }
  }
  return pos;
}

function invDrawGraph(data) {
  const holder = $("inv-graph");
  holder.innerHTML = "";
  if (data.nodes.length <= 1) {
    holder.append(el("p", "empty", "Keine Beziehungen in den gewählten Arten. Weitere Arten oben einschalten."));
    return;
  }
  const ns = "http://www.w3.org/2000/svg";
  const pos = invLayout(data.nodes, data.edges, data.anchor);
  const xs = [...pos.values()].map((p) => p.x);
  const ys = [...pos.values()].map((p) => p.y);
  const fit = {
    x: Math.min(...xs) - 90,
    y: Math.min(...ys) - 50,
    w: Math.max(...xs) - Math.min(...xs) + 180,
    h: Math.max(...ys) - Math.min(...ys) + 100,
  };
  let view = { ...fit };
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Beziehungen des gewählten Werts");
  const apply = () => svg.setAttribute("viewBox", `${view.x} ${view.y} ${view.w} ${view.h}`);
  apply();
  const edgeLayer = document.createElementNS(ns, "g");
  const nodeLayer = document.createElementNS(ns, "g");
  svg.append(edgeLayer, nodeLayer);
  const maxWeight = Math.max(1, ...data.edges.map((edge) => edge.weight));
  const edgeEls = [];
  const nodeEls = new Map();
  const byId = new Map(data.nodes.map((node) => [node.id, node]));

  for (const edge of data.edges) {
    const a = pos.get(edge.a);
    const b = pos.get(edge.b);
    if (!a || !b) continue;
    const line = document.createElementNS(ns, "line");
    for (const [key, value] of [["x1", a.x], ["y1", a.y], ["x2", b.x], ["y2", b.y]]) line.setAttribute(key, String(value));
    line.setAttribute("class", "edge");
    line.setAttribute("stroke-width", String(1 + 3 * Math.log1p(edge.weight) / Math.log1p(maxWeight)));
    const hit = line.cloneNode();
    hit.setAttribute("class", "edge hit");
    const title = document.createElementNS(ns, "title");
    title.textContent = `${edge.weight} gemeinsame Ereignisse`;
    hit.append(title);
    hit.addEventListener("click", (event) => {
      event.stopPropagation();
      invGraphSelectEdge(edge, byId);
    });
    edgeLayer.append(line, hit);
    edgeEls.push({ edge, line });
  }

  for (const node of data.nodes) {
    const p = pos.get(node.id);
    const meta = kindOf(node.kind);
    const group = document.createElementNS(ns, "g");
    group.setAttribute("class", "node" + (node.id === data.anchor ? " anchor" : ""));
    group.setAttribute("transform", `translate(${p.x} ${p.y})`);
    group.setAttribute("tabindex", "0");
    const radius = node.id === data.anchor ? 13 : 7 + Math.min(6, Math.log1p(node.events || 1));
    const circle = document.createElementNS(ns, "circle");
    circle.setAttribute("r", String(radius));
    circle.setAttribute("fill", `var(--${meta.color})`);
    if (node.common || node.generic) circle.setAttribute("stroke-dasharray", "3 2");
    const tag = document.createElementNS(ns, "text");
    tag.setAttribute("class", "tag");
    tag.textContent = meta.tag;
    const label = document.createElementNS(ns, "text");
    const shown = node.display || node.value;
    label.textContent = shown.length > 34 ? shown.slice(0, 32) + "…" : shown;
    label.setAttribute("x", String(radius + 4));
    label.setAttribute("y", "4");
    const title = document.createElementNS(ns, "title");
    title.textContent = `${meta.label}: ${shown}\n${node.events} Vorkommen in ${node.sources} Logs` +
      (node.common ? "\nhäufig" : "") + (node.generic ? "\nallgemein" : "") + "\nKlick: auswählen · Doppelklick: hier zentrieren";
    group.append(title, circle, tag, label);
    group.addEventListener("click", (event) => {
      event.stopPropagation();
      invGraphSelectNode(node, edgeEls, nodeEls);
    });
    group.addEventListener("dblclick", (event) => {
      event.stopPropagation();
      invOpenGraph(node.id).catch((error) => setStatus(error.message, "error"));
    });
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter") invGraphSelectNode(node, edgeEls, nodeEls);
    });
    nodeLayer.append(group);
    nodeEls.set(node.id, group);
  }

  // Zoom with the wheel around the pointer, pan by dragging the background.
  const toGraph = (event) => {
    const box = svg.getBoundingClientRect();
    return {
      x: view.x + ((event.clientX - box.left) / box.width) * view.w,
      y: view.y + ((event.clientY - box.top) / box.height) * view.h,
    };
  };
  const zoom = (factor, center) => {
    const c = center || { x: view.x + view.w / 2, y: view.y + view.h / 2 };
    const w = Math.min(fit.w * 6, Math.max(fit.w / 8, view.w * factor));
    const h = (w / view.w) * view.h;
    view = { x: c.x - ((c.x - view.x) / view.w) * w, y: c.y - ((c.y - view.y) / view.h) * h, w, h };
    apply();
  };
  svg.addEventListener("wheel", (event) => {
    event.preventDefault();
    zoom(event.deltaY > 0 ? 1.15 : 1 / 1.15, toGraph(event));
  }, { passive: false });
  let drag = null;
  svg.addEventListener("pointerdown", (event) => {
    if (event.target.closest(".node") || event.target.classList.contains("hit")) return;
    drag = { x: event.clientX, y: event.clientY, view: { ...view } };
    svg.setPointerCapture(event.pointerId);
    svg.classList.add("panning");
  });
  svg.addEventListener("pointermove", (event) => {
    if (!drag) return;
    const box = svg.getBoundingClientRect();
    view = {
      ...drag.view,
      x: drag.view.x - ((event.clientX - drag.x) / box.width) * drag.view.w,
      y: drag.view.y - ((event.clientY - drag.y) / box.height) * drag.view.h,
    };
    apply();
  });
  const stop = () => {
    drag = null;
    svg.classList.remove("panning");
  };
  svg.addEventListener("pointerup", stop);
  svg.addEventListener("pointercancel", stop);
  svg.addEventListener("click", () => invGraphClear(edgeEls, nodeEls));

  const controls = el("div", "inv-graph-zoom");
  for (const [text, title, handler] of [
    ["+", "Vergrößern", () => zoom(1 / 1.3)],
    ["−", "Verkleinern", () => zoom(1.3)],
    ["⤢", "Alles zeigen", () => { view = { ...fit }; apply(); }],
  ]) {
    const button = el("button", "btn", text);
    button.type = "button";
    button.title = title;
    button.setAttribute("aria-label", title);
    button.onclick = handler;
    controls.append(button);
  }
  holder.append(svg, controls);
  const info = $("inv-graph-info");
  info.innerHTML = "";
  info.append(el("p", "hint", `${data.nodes.length} Werte, ${data.edges.length} Verbindungen. Gezeigt werden die engsten direkten Beziehungen und ein Schritt weiter über Nachrichten und Sitzungen. Linienstärke: Zahl gemeinsamer Ereignisse.`));
}

function invGraphClear(edgeEls, nodeEls) {
  for (const { line } of edgeEls) line.classList.remove("on", "dim");
  for (const group of nodeEls.values()) group.classList.remove("on", "dim");
}

function invGraphSelectNode(node, edgeEls, nodeEls) {
  const neighbours = new Set([node.id]);
  for (const { edge, line } of edgeEls) {
    const touches = edge.a === node.id || edge.b === node.id;
    line.classList.toggle("on", touches);
    line.classList.toggle("dim", !touches);
    if (touches) {
      neighbours.add(edge.a);
      neighbours.add(edge.b);
    }
  }
  for (const [id, group] of nodeEls) {
    group.classList.toggle("on", id === node.id);
    group.classList.toggle("dim", !neighbours.has(id));
  }
  const info = $("inv-graph-info");
  info.innerHTML = "";
  const line = el("div", "ent-list");
  line.append(entityChip(node), el("span", "hint", `${node.events} Vorkommen in ${plural(node.sources, "Log", "Logs")}`));
  const actions = el("div", "card-actions card-actions-start");
  for (const [label, handler, className] of [
    ["Spur zeigen", () => invAddAnchor(node, true), "btn btn-primary"],
    ["Details", () => invOpenEntity(node.id), "btn"],
    ["Hier zentrieren", () => invOpenGraph(node.id), "btn btn-quiet"],
  ]) {
    const button = el("button", className, label);
    button.type = "button";
    button.onclick = () => Promise.resolve(handler()).catch((error) => setStatus(error.message, "error"));
    actions.append(button);
  }
  info.append(line, actions);
}

function invGraphSelectEdge(edge, byId) {
  const a = byId.get(edge.a);
  const b = byId.get(edge.b);
  const info = $("inv-graph-info");
  info.innerHTML = "";
  const line = el("div", "ent-list");
  line.append(entityChip(a), el("span", null, "↔"), entityChip(b));
  info.append(line, el("p", "hint", `${plural(edge.weight, "gemeinsames Ereignis", "gemeinsame Ereignisse")}. Gilt diese Verbindung nicht, kann sie ausgeschlossen werden; sie fehlt dann in Graph, Spur und Listen.`));
  const exclude = el("button", "btn btn-danger-quiet", "Verknüpfung ausschließen");
  exclude.type = "button";
  exclude.onclick = () => invExcludeLink(edge.a, edge.b).catch((error) => setStatus(error.message, "error"));
  info.append(exclude);
}

/* ── Suggestions ─────────────────────────────────────────────────────── */

function invCloseSuggest() {
  // A request still under way must not open the list again.
  clearTimeout(inv.suggest.timer);
  inv.suggest.seq += 1;
  $("inv-suggest").hidden = true;
  $("inv-query").setAttribute("aria-expanded", "false");
  inv.suggest.items = [];
  inv.suggest.index = -1;
}

async function invLoadSuggest() {
  const text = $("inv-query").value.trim();
  if (text.length < 2 || !inv.current) {
    invCloseSuggest();
    return;
  }
  const seq = ++inv.suggest.seq;
  const data = await invApi("suggest", { query: text }, 1);
  if (seq !== inv.suggest.seq) return;
  inv.suggest.items = data.items;
  inv.suggest.index = -1;
  const list = $("inv-suggest");
  list.innerHTML = "";
  for (const [index, item] of data.items.entries()) {
    const li = el("li");
    li.setAttribute("role", "option");
    li.id = `inv-suggest-${index}`;
    const meta = kindOf(item.kind);
    const tag = el("span", "ent");
    tag.style.setProperty("--c", `var(--${meta.color})`);
    tag.append(el("span", "k", meta.tag), el("span", null, meta.label));
    li.append(tag, el("span", "value", item.display || item.value),
      el("span", "meta", `${item.events.toLocaleString("de-DE")}× · ${plural(item.sources, "Log", "Logs")}${item.common ? " · häufig" : ""}${item.generic ? " · allgemein" : ""}`));
    li.onmousedown = (event) => {
      event.preventDefault();
      invPickSuggest(index);
    };
    list.append(li);
  }
  list.hidden = !data.items.length;
  $("inv-query").setAttribute("aria-expanded", String(!list.hidden));
}

function invPickSuggest(index) {
  const item = inv.suggest.items[index];
  invCloseSuggest();
  if (!item) return;
  invAddAnchor(item, false).catch((error) => setStatus(error.message, "error"));
}

function invMoveSuggest(step) {
  const items = $("inv-suggest").children;
  if (!items.length) return;
  inv.suggest.index = (inv.suggest.index + step + items.length) % items.length;
  for (const [index, item] of [...items].entries()) item.setAttribute("aria-selected", String(index === inv.suggest.index));
  $("inv-query").setAttribute("aria-activedescendant", items[inv.suggest.index].id);
  items[inv.suggest.index].scrollIntoView({ block: "nearest" });
}

/* ── Export ──────────────────────────────────────────────────────────── */

function invUpdateExportButton() {
  const button = document.querySelector('[data-action="inv-export"]');
  button.disabled = inv.selected.size === 0;
  button.textContent = inv.selected.size ? `Für KI exportieren (${inv.selected.size.toLocaleString("de-DE")}) …` : "Für KI exportieren …";
}

const invExport = { result: null, released: false };

async function invOpenExport() {
  if (!inv.selected.size) throw new Error("Zuerst Ereignisse in der Zeitleiste wählen.");
  const dialog = $("inv-export-dialog");
  $("inv-export-reviewed").checked = false;
  dialog.showModal();
  await invExportPreview();
}

async function invExportPreview() {
  invExport.result = null;
  invExport.released = false;
  $("inv-export-copy").disabled = true;
  $("inv-export-save").disabled = true;
  $("inv-export-release").disabled = true;
  $("inv-export-note").textContent = "Vorschau wird erstellt …";
  $("inv-export-status").innerHTML = "";
  $("inv-export-text").textContent = "";
  let result;
  try {
    result = await invApi("export", { events: [...inv.selected], useStore: $("inv-export-store").checked, confirm: false });
  } catch (error) {
    $("inv-export-note").textContent = "";
    $("inv-export-status").append(el("p", "error-line", error.message));
    return;
  }
  invExport.result = result;
  invRenderExport(result);
}

function invRenderExport(result) {
  const status = $("inv-export-status");
  status.innerHTML = "";
  const replaced = Object.entries(result.stats || {}).map(([category, count]) => `${count}× ${CATEGORY_LABELS[category] || category}`);
  status.append(el("p", "result-line", `${plural(result.events, "Ereignis", "Ereignisse")}; ersetzt: ${replaced.join(", ") || "nichts"}.`));
  const review = new Map();
  for (const mark of result.marks || []) {
    if (mark.leak) continue;
    const label = mark.category === "Secret" ? "Kennwort-/Schlüsselwort" : CATEGORY_LABELS[mark.category] || mark.category;
    review.set(label, (review.get(label) || 0) + 1);
  }
  if (result.blocked) {
    const kinds = [...new Set(result.leaks.map((leak) => leak.kind))].join(", ");
    status.append(el("p", "error-line", `Gesperrt: ${plural(result.leaks.length, "Originalwert ist", "Originalwerte sind")} noch lesbar (${kinds}), rot markiert. Die betroffenen Ereignisse abwählen oder den Wert im Anonymisieren-Reiter als eigenen Begriff hinterlegen.`));
  } else if (review.size) {
    status.append(el("p", "warn-line", `Bitte prüfen: ${[...review].map(([label, count]) => `${count}× ${label}`).join(", ")} – orange markiert. Freigabe erst nach Bestätigung.`));
  } else {
    status.append(el("p", "ok", "Keine Originalwerte und nichts Auffälliges gefunden."));
  }
  if (!result.reversible) status.append(el("p", "hint", "Ohne Store: Die Platzhalter lassen sich später nicht zurückwandeln."));
  $("inv-export-reviewed-row").hidden = result.blocked || !review.size;
  $("inv-export-release").disabled = result.blocked;
  $("inv-export-note").textContent = result.blocked ? "Export gesperrt" : "Vorschau – noch nicht freigegeben";
  invExportText(result.text, result.marks || []);
}

function invExportText(text, marks) {
  const holder = $("inv-export-text");
  holder.innerHTML = "";
  let cursor = 0;
  for (const mark of marks) {
    if (mark.start < cursor) continue;
    holder.append(text.slice(cursor, mark.start));
    const node = el("mark", mark.leak ? "leak" : "review", text.slice(mark.start, mark.end));
    node.title = mark.leak ? `Originalwert (${mark.label}) – sperrt den Export` : `Bitte prüfen: ${mark.category === "Secret" ? "Kennwort-/Schlüsselwort" : CATEGORY_LABELS[mark.category] || mark.category}`;
    holder.append(node);
    cursor = mark.end;
  }
  holder.append(text.slice(cursor));
  const first = holder.querySelector("mark.leak, mark.review");
  if (first) first.scrollIntoView({ block: "center" });
}

async function invReleaseExport() {
  const result = invExport.result;
  if (!result || result.blocked) return;
  const needsReview = !$("inv-export-reviewed-row").hidden;
  if (needsReview && !$("inv-export-reviewed").checked) {
    $("inv-export-note").textContent = "Bitte zuerst die markierten Stellen prüfen und bestätigen.";
    return;
  }
  const released = await invApi("export", {
    events: [...inv.selected],
    useStore: $("inv-export-store").checked,
    confirm: true,
    reviewed: $("inv-export-reviewed").checked || !needsReview,
  });
  invExport.result = released;
  invExport.released = true;
  invRenderExport(released);
  $("inv-export-reviewed-row").hidden = true;
  $("inv-export-release").disabled = true;
  $("inv-export-copy").disabled = false;
  $("inv-export-save").disabled = false;
  $("inv-export-note").textContent = released.reversible
    ? "Freigegeben. Platzhalter sind im Store gesichert; die Antwort lässt sich im Anonymisieren-Reiter zurückwandeln."
    : "Freigegeben.";
}

async function invCopyExport() {
  if (!invExport.released) return;
  const text = invExport.result.text;
  try {
    await navigator.clipboard.writeText(text);
  } catch (error) {
    const area = el("textarea");
    area.value = text;
    document.body.append(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  $("inv-export-note").textContent = "In die Zwischenablage kopiert.";
}

function invSaveExport() {
  if (!invExport.released) return;
  const now = new Date();
  const name = `logmasque-export-${now.getFullYear()}${pad2(now.getMonth() + 1)}${pad2(now.getDate())}-${pad2(now.getHours())}${pad2(now.getMinutes())}.txt`;
  const blob = new Blob([invExport.result.text], { type: "text/plain;charset=utf-8" });
  const link = el("a");
  link.href = URL.createObjectURL(blob);
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 2000);
  $("inv-export-note").textContent = `Gespeichert als ${name} (Download-Ordner des Browsers).`;
}

/* ── Wiring ──────────────────────────────────────────────────────────── */

Object.assign(actions, {
  "inv-new": async () => {
    const name = await askText("Neue Untersuchung", "Ein Name, zum Beispiel die Ticketnummer. Er bleibt lokal.", "");
    if (name === null) return;
    const overview = await invApi("create", { name });
    invResetView();
    await invLoadList(overview.id);
  },
  "inv-delete": async () => {
    if (!inv.current) return;
    const ok = await askConfirm(
      "Untersuchung löschen",
      "Der Index dieser Untersuchung wird gelöscht. Die Logdateien selbst bleiben unverändert.",
      "Löschen"
    );
    if (!ok) return;
    await invApi("delete", { id: inv.current });
    invResetView();
    inv.current = null;
    await invLoadList();
  },
  "inv-add-files": async () => invScan(await pickPath({ kind: "files", title: "Logdateien wählen" })),
  "inv-add-folder": async () => {
    const path = await pickPath({ kind: "dir", title: "Ordner mit Logdateien wählen" });
    if (path) await invScan([path]);
  },
  "inv-scan-close": async () => {
    inv.scan = null;
    invRenderScan();
  },
  "inv-import-start": invStartImport,
  "inv-refresh": async () => invSearch(inv.offset),
  "inv-cancel": async () => {
    if (inv.job) await api("/api/job/cancel", { id: inv.job });
  },
  "inv-default-tz": async () => {
    const mode = $("inv-default-tz").value;
    let offset = null;
    if (mode === "fixed") {
      offset = parseOffset($("inv-default-offset").value);
      if (offset === null) throw new Error("Zeitzone bitte als Abweichung von UTC angeben, zum Beispiel +01:00.");
    }
    await invTimeJob({ mode, offset });
    await invSearch(inv.offset);
  },
  "inv-search": async () => {
    invCloseSuggest();
    await invSearch(0);
  },
  "inv-reset-filters": async () => {
    $("inv-from").value = "";
    $("inv-to").value = "";
    $("inv-details").checked = false;
    inv.sources.clear();
    inv.etypes.clear();
    for (const box of document.querySelectorAll("#inv-levels [data-level]")) box.checked = box.dataset.level !== "3";
    $("inv-temporal").value = "0";
    invRenderFilters();
    await invSearch(0);
  },
  "inv-prev": async () => invSearch(Math.max(0, inv.offset - inv.limit)),
  "inv-next": async () => invSearch(inv.offset + inv.limit),
  "inv-select-all": async () => {
    if (inv.context) {
      for (const row of document.querySelectorAll("#inv-rows .inv-row")) inv.selected.add(Number(row.dataset.id));
    } else {
      const data = await invApi("search", Object.assign(invPayload(0), { idsOnly: true, limit: 5000 }));
      for (const id of data.ids) inv.selected.add(id);
      if (data.ids.length >= 5000) setStatus("Höchstens 5000 Ereignisse gewählt", null);
    }
    for (const box of document.querySelectorAll("#inv-rows .inv-row input")) box.checked = true;
    invUpdateExportButton();
  },
  "inv-select-none": async () => {
    inv.selected.clear();
    for (const box of document.querySelectorAll("#inv-rows .inv-row input")) box.checked = false;
    invUpdateExportButton();
  },
  "inv-export": invOpenExport,
});

$("inv-select").addEventListener("change", () => {
  const id = $("inv-select").value;
  if (id) invOpen(id).catch((error) => setStatus(error.message, "error"));
});
$("inv-default-tz").addEventListener("change", () => {
  $("inv-default-offset").hidden = $("inv-default-tz").value !== "fixed";
});
$("inv-query").addEventListener("input", () => {
  clearTimeout(inv.suggest.timer);
  inv.suggest.timer = setTimeout(() => invLoadSuggest().catch(() => invCloseSuggest()), 180);
});
$("inv-query").addEventListener("keydown", (event) => {
  const open = !$("inv-suggest").hidden;
  if (event.key === "ArrowDown" && open) {
    event.preventDefault();
    invMoveSuggest(1);
  } else if (event.key === "ArrowUp" && open) {
    event.preventDefault();
    invMoveSuggest(-1);
  } else if (event.key === "Escape") {
    invCloseSuggest();
  } else if (event.key === "Enter") {
    event.preventDefault();
    if (open && inv.suggest.index >= 0) invPickSuggest(inv.suggest.index);
    else actions["inv-search"]().catch((error) => setStatus(error.message, "error"));
  }
});
$("inv-query").addEventListener("blur", () => setTimeout(invCloseSuggest, 120));
for (const id of ["inv-from", "inv-to", "inv-details", "inv-temporal"]) {
  $(id).addEventListener("change", () => invSearch(0).catch((error) => setStatus(error.message, "error")));
}
for (const box of document.querySelectorAll("#inv-levels [data-level]")) {
  box.addEventListener("change", () => invSearch(0).catch((error) => setStatus(error.message, "error")));
}
$("inv-side-tabs").addEventListener("click", (event) => {
  const tab = event.target.closest("[data-side]");
  if (!tab) return;
  invSide(tab.dataset.side);
  if (tab.dataset.side === "graph") {
    invRenderGraphKinds();
    const target = inv.entityId || (inv.anchors[0] && inv.anchors[0].id);
    if (target && (!inv.graph || inv.graph.anchor !== target)) invOpenGraph(target).catch((error) => setStatus(error.message, "error"));
  }
});
// Drop-downs close when the pointer goes elsewhere, like a menu.
document.addEventListener("mousedown", (event) => {
  for (const details of document.querySelectorAll("details.dropdown[open]")) {
    if (!details.contains(event.target)) details.open = false;
  }
});
$("inv-export-store").addEventListener("change", () => invExportPreview());
$("inv-scan-window").addEventListener("change", () => invRenderScan());
for (const id of ["inv-scan-from", "inv-scan-to", "inv-scan-outside"]) {
  $(id).addEventListener("change", () => {
    if (id !== "inv-scan-outside") $("inv-scan-window").checked = true;
    invRenderScan();
  });
}
$("inv-export-release").addEventListener("click", () => invReleaseExport().catch((error) => {
  $("inv-export-note").textContent = error.message;
}));
$("inv-export-copy").addEventListener("click", () => invCopyExport());
$("inv-export-save").addEventListener("click", () => invSaveExport());

document.addEventListener("viewchange", (event) => {
  if (event.detail === "investigate" && !inv.loaded) {
    invLoadList().catch((error) => setStatus(error.message, "error"));
  }
});
