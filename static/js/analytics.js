function el(id) {
  return document.getElementById(id);
}

function showAlert(message, type = "info") {
  const box = el("analyticsAlert");
  if (!box) return;
  box.textContent = message || "";
  box.className = message ? `alert ${type}` : "";
}

async function apiGet(path, params = {}) {
  const url = new URL(path, window.location.origin);
  Object.entries(params).forEach(([k, v]) => {
    if (v === undefined || v === null || v === "") return;
    url.searchParams.set(k, String(v));
  });
  const res = await fetch(url.toString(), { credentials: "same-origin" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.success === false) {
    const msg = data?.error?.message || data?.error || `Request failed: ${res.status}`;
    throw new Error(msg);
  }
  return data.data;
}

function fmtDate(epochSec) {
  if (!epochSec) return "-";
  const d = new Date(Number(epochSec) * 1000);
  if (!Number.isFinite(d.getTime())) return "-";
  return d.toISOString().slice(0, 16).replace("T", " ");
}

// --- Weekly summary chart ---
let weeklyChart = null;

function renderWeeklySummary(summary) {
  const ctx = el("weeklySummaryChart")?.getContext("2d");
  if (!ctx) return;

  const labels = summary.labels || [];
  const dangerous = summary.dangerous || [];
  const suspicious = summary.suspicious || [];

  if (weeklyChart) {
    weeklyChart.data.labels = labels;
    weeklyChart.data.datasets[0].data = suspicious;
    weeklyChart.data.datasets[1].data = dangerous;
    weeklyChart.update();
    return;
  }

  weeklyChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [
        { label: "Suspicious", data: suspicious, backgroundColor: "#f59e0b" },
        { label: "Dangerous", data: dangerous, backgroundColor: "#ef4444" },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { position: "bottom" } },
      scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } },
    },
  });
}

// --- Recurring actors tables ---
function renderActorTable(tbodyId, rows, keyName) {
  const tbody = el(tbodyId);
  if (!tbody) return;
  tbody.innerHTML = "";

  if (!rows || rows.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "empty";
    td.textContent = "No recurring activity found.";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (const r of rows.slice(0, 20)) {
    const tr = document.createElement("tr");
    const values = [
      r.actor || "-",
      String(r.days_active ?? 0),
      String(r.total_events ?? 0),
      String(r.total_dangerous ?? 0),
      (r.worst_risk ?? 0).toFixed(2),
    ];
    for (const v of values) {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    }
    tr.title = `First: ${fmtDate(r.first_seen)} · Last: ${fmtDate(r.last_seen)}`;
    tbody.appendChild(tr);
  }
}

// --- Top threat categories chart ---
let topThreatsChart = null;

function renderTopThreats(rows) {
  const ctx = el("topThreatsChart")?.getContext("2d");
  if (!ctx) return;

  const labels = (rows || []).map((r) => r.category);
  const data = (rows || []).map((r) => r.total_events);

  if (topThreatsChart) {
    topThreatsChart.data.labels = labels;
    topThreatsChart.data.datasets[0].data = data;
    topThreatsChart.update();
    return;
  }

  topThreatsChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: "#6366f1",
      }],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true } },
    },
  });
}

// --- Heatmap ---
function renderHeatmap(payload) {
  const container = el("heatmapContainer");
  if (!container) return;
  container.innerHTML = "";

  const hours = payload.hours || [];
  const rows = payload.rows || [];
  const maxVal = payload.max || 0;

  // Header row: hour labels
  const headerRow = document.createElement("div");
  headerRow.className = "analytics-heatmap-row analytics-heatmap-row--header";
  const corner = document.createElement("span");
  corner.className = "analytics-heatmap-label";
  headerRow.appendChild(corner);
  for (const h of hours) {
    const cell = document.createElement("span");
    cell.className = "analytics-heatmap-hour";
    cell.textContent = h;
    headerRow.appendChild(cell);
  }
  container.appendChild(headerRow);

  // Day rows
  for (const row of rows) {
    const rowEl = document.createElement("div");
    rowEl.className = "analytics-heatmap-row";

    const label = document.createElement("span");
    label.className = "analytics-heatmap-label";
    label.textContent = row.day;
    rowEl.appendChild(label);

    for (let h = 0; h < row.cells.length; h++) {
      const val = row.cells[h] || 0;
      const cell = document.createElement("span");
      cell.className = "analytics-heatmap-cell";
      const intensity = maxVal > 0 ? val / maxVal : 0;
      // Green → amber → red scale
      if (val === 0) {
        cell.style.background = "rgba(148, 163, 184, 0.06)";
      } else if (intensity < 0.34) {
        cell.style.background = `rgba(16, 185, 129, ${0.25 + intensity * 0.6})`;
      } else if (intensity < 0.67) {
        cell.style.background = `rgba(245, 158, 11, ${0.35 + intensity * 0.6})`;
      } else {
        cell.style.background = `rgba(239, 68, 68, ${0.4 + intensity * 0.6})`;
      }
      cell.title = `${row.day} ${hours[h]}:00 — ${val} dangerous event${val === 1 ? "" : "s"}`;
      cell.setAttribute("aria-label", cell.title);
      rowEl.appendChild(cell);
    }
    container.appendChild(rowEl);
  }
}

// --- Detected patterns cards ---
function renderPatterns(payload) {
  const grid = el("patternsGrid");
  if (!grid) return;
  grid.innerHTML = "";

  const all = [
    ...(payload.ip_patterns || []).map((p) => ({ ...p, kind: "IP" })),
    ...(payload.host_patterns || []).map((p) => ({ ...p, kind: "Host" })),
  ];

  if (all.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "No periodic patterns detected in the selected window.";
    grid.appendChild(empty);
    return;
  }

  for (const p of all.slice(0, 12)) {
    const card = document.createElement("article");
    card.className = "card analytics-pattern-card";

    const header = document.createElement("div");
    header.className = "analytics-pattern-header";

    const badge = document.createElement("span");
    badge.className = "analytics-pattern-badge";
    badge.textContent = p.kind;

    const actor = document.createElement("strong");
    actor.className = "analytics-pattern-actor";
    actor.textContent = p.actor;

    header.appendChild(badge);
    header.appendChild(actor);
    card.appendChild(header);

    const line1 = document.createElement("p");
    line1.className = "analytics-pattern-line";
    line1.textContent = `Typically appears on ${p.day_name} — ${Math.round(p.share * 100)}% of its activity.`;
    card.appendChild(line1);

    const line2 = document.createElement("p");
    line2.className = "analytics-pattern-line small";
    line2.textContent =
      `Observed ${p.weeks_observed} week${p.weeks_observed === 1 ? "" : "s"}, ` +
      `avg ${p.avg_events_per_week} event${p.avg_events_per_week === 1 ? "" : "s"}/week` +
      (p.top_category ? ` · top signal: ${p.top_category}` : "");
    card.appendChild(line2);

    grid.appendChild(card);
  }
}

// --- Orchestration ---
async function loadAll() {
  showAlert("", "info");

  const weeks = Number(el("heatmapWeeks")?.value || 4);

  const results = await Promise.allSettled([
    apiGet("/analytics/api/weekly-summary", { weeks: 12 }),
    apiGet("/analytics/api/heatmap", { weeks }),
    apiGet("/analytics/api/recurring-ips", { min_days: 3, days: 30 }),
    apiGet("/analytics/api/recurring-hosts", { min_days: 3, days: 30 }),
    apiGet("/analytics/api/top-threats", { days: 30 }),
    apiGet("/analytics/api/patterns", { days: 60 }),
  ]);

  const [summary, heatmap, ips, hosts, threats, patterns] = results;

  if (summary.status === "fulfilled") renderWeeklySummary(summary.value);
  if (heatmap.status === "fulfilled") renderHeatmap(heatmap.value);
  if (ips.status === "fulfilled") renderActorTable("recurringIpsTbody", ips.value);
  if (hosts.status === "fulfilled") renderActorTable("recurringHostsTbody", hosts.value);
  if (threats.status === "fulfilled") renderTopThreats(threats.value);
  if (patterns.status === "fulfilled") renderPatterns(patterns.value);

  const failed = results.filter((r) => r.status === "rejected");
  if (failed.length) {
    const first = failed[0].reason;
    showAlert(first?.message || "Some analytics queries failed.", "error");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  if (!window.Chart) {
    showAlert("Chart library failed to load.", "error");
  }

  Chart.defaults.color = "#8b9cb3";
  Chart.defaults.borderColor = "rgba(148, 163, 184, 0.12)";
  Chart.defaults.font.family = "'DM Sans', system-ui, sans-serif";

  el("heatmapWeeks")?.addEventListener("change", () => {
    loadAll().catch((e) => showAlert(e.message, "error"));
  });

  loadAll().catch((e) => showAlert(e.message || "Failed to load analytics.", "error"));
});