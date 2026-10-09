function el(id) { return document.getElementById(id); }

function showAlert(message, type = "info") {
  const box = el("auditAlert");
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
    throw new Error(data?.error?.message || data?.error || `HTTP ${res.status}`);
  }
  return data;
}

function fmtTs(ts) {
  if (!ts) return "—";
  const d = new Date(Number(ts) * 1000);
  if (!Number.isFinite(d.getTime())) return "—";
  return d.toISOString().slice(0, 19).replace("T", " ");
}

let currentCursor = null;
let lastRows = [];

function renderTable(rows) {
  const tbody = el("auditTbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  lastRows = rows;

  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 6; td.className = "empty"; td.textContent = "No audit entries match your filters.";
    tr.appendChild(td); tbody.appendChild(tr);
    return;
  }

  rows.forEach((r, idx) => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    const target = r.target_type ? `${r.target_type}${r.target_id ? " #" + r.target_id : ""}` : "—";
    const values = [
      fmtTs(r.ts),
      r.actor_username || (r.actor_id ? `user #${r.actor_id}` : "—"),
      r.action,
      target,
      r.outcome,
      r.actor_ip || "—",
    ];
    values.forEach((v, i) => {
      const td = document.createElement("td");
      if (i === 4) {
        const span = document.createElement("span");
        span.className = "tag-pill";
        if (r.outcome === "failure") {
          span.style.borderColor = "#7f1d1d"; span.style.background = "#1f0b0b"; span.style.color = "#fecaca";
        } else if (r.outcome === "denied") {
          span.style.borderColor = "#92400e"; span.style.background = "#1a1206"; span.style.color = "#fde68a";
        } else {
          span.style.borderColor = "#065f46"; span.style.background = "#052e2a"; span.style.color = "#a7f3d0";
        }
        span.textContent = r.outcome;
        td.appendChild(span);
      } else {
        td.textContent = v;
      }
      tr.appendChild(td);
    });
    tr.addEventListener("click", () => openDetail(r));
    tbody.appendChild(tr);
  });
}

function renderPager(meta) {
  const host = el("auditPager");
  if (!host) return;
  host.innerHTML = "";
  const next = meta && meta.next_cursor;

  const prev = document.createElement("button");
  prev.type = "button"; prev.className = "secondary";
  prev.textContent = "First page"; prev.style.width = "auto";
  prev.addEventListener("click", () => { currentCursor = null; loadEntries(); });

  const nxt = document.createElement("button");
  nxt.type = "button"; nxt.className = "secondary";
  nxt.textContent = "Next"; nxt.style.width = "auto";
  nxt.style.marginLeft = "8px";
  nxt.disabled = !next;
  nxt.addEventListener("click", () => {
    currentCursor = next;
    loadEntries();
  });

  host.appendChild(prev);
  host.appendChild(nxt);
}

async function loadActions() {
  const data = await apiGet("/audit/api/actions");
  const sel = el("auditFilterAction");
  if (!sel) return;
  for (const action of (data.data || [])) {
    const opt = document.createElement("option");
    opt.value = action; opt.textContent = action;
    sel.appendChild(opt);
  }
}

async function loadStats() {
  const res = await apiGet("/audit/api/stats", { days: 7 });
  const d = res.data || {};
  el("auditTotal").textContent = d.total ?? 0;
  el("auditFailures").textContent = d.failures ?? 0;
  el("auditActors").textContent = d.distinct_actors ?? 0;
}

async function loadEntries() {
  showAlert("", "info");
  try {
    const params = {
      action: el("auditFilterAction")?.value || "",
      actor: el("auditFilterActor")?.value?.trim() || "",
      outcome: el("auditFilterOutcome")?.value || "",
      limit: 100,
    };
    if (currentCursor) {
      params.before_ts = currentCursor.before_ts;
      params.before_id = currentCursor.before_id;
    }
    const res = await apiGet("/audit/api/entries", params);
    renderTable(res.data || []);
    renderPager(res.meta || {});
  } catch (e) {
    showAlert(e.message || "Failed to load entries.", "error");
  }
}

function openDetail(entry) {
  const modal = el("auditDetailModal");
  const pre = el("auditDetailPre");
  if (!modal || !pre) return;
  pre.textContent = JSON.stringify(entry, null, 2);
  modal.classList.add("open");
}

document.addEventListener("DOMContentLoaded", async () => {
  const modal = el("auditDetailModal");
  const closeBtn = el("closeAuditDetail");
  const closeModal = () => modal?.classList.remove("open");
  closeBtn?.addEventListener("click", closeModal);
  modal?.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal?.classList.contains("open")) closeModal();
  });

  el("auditApplyBtn")?.addEventListener("click", () => { currentCursor = null; loadEntries(); });
  el("auditResetBtn")?.addEventListener("click", () => {
    el("auditFilterAction").value = "";
    el("auditFilterActor").value = "";
    el("auditFilterOutcome").value = "";
    currentCursor = null;
    loadEntries();
  });

  try {
    await Promise.all([loadActions(), loadStats(), loadEntries()]);
  } catch (e) {
    showAlert(e.message || "Failed to load audit page.", "error");
  }
});