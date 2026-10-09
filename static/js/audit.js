function el(id) { return document.getElementById(id); }

function showAlert(message, type = "info") {
  const box = el("auditAlert");
  if (!box) return;
  box.textContent = message || "";
  box.className = message ? `alert ${type}` : "audit-alert-hidden";
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

// Cursor stack: index 0 is the first page (null cursor).
// Advancing pushes onto the stack; going back pops.
let cursorStack = [null];
let cursorIndex = 0;
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

  rows.forEach((r) => {
    const tr = document.createElement("tr");
    tr.className = "audit-row";
    tr.tabIndex = 0;
    tr.setAttribute("role", "button");

    const ts = fmtTs(r.ts);
    const actor = r.actor_username || (r.actor_id ? `user #${r.actor_id}` : "—");
    const target = r.target_type
      ? `${r.target_type}${r.target_id ? " #" + r.target_id : ""}`
      : "—";
    const ip = r.actor_ip || "—";

    // Timestamp
    const tdTs = document.createElement("td");
    tdTs.className = "audit-cell audit-cell--mono";
    tdTs.textContent = ts;
    tr.appendChild(tdTs);

    // Actor
    const tdActor = document.createElement("td");
    tdActor.className = "audit-cell";
    if (r.actor_username) {
      const strong = document.createElement("strong");
      strong.className = "audit-actor";
      strong.textContent = r.actor_username;
      tdActor.appendChild(strong);
    } else if (r.actor_id) {
      const muted = document.createElement("span");
      muted.className = "audit-actor audit-actor--muted";
      muted.textContent = `user #${r.actor_id}`;
      tdActor.appendChild(muted);
    } else {
      tdActor.textContent = "—";
    }
    tr.appendChild(tdActor);

    // Action
    const tdAction = document.createElement("td");
    tdAction.className = "audit-cell";
    const actionCode = document.createElement("code");
    actionCode.className = "audit-action";
    actionCode.textContent = r.action || "—";
    tdAction.appendChild(actionCode);
    tr.appendChild(tdAction);

    // Target
    const tdTarget = document.createElement("td");
    tdTarget.className = "audit-cell audit-cell--mono";
    tdTarget.textContent = target;
    tr.appendChild(tdTarget);

    // Outcome — colored pill via CSS classes
    const tdOutcome = document.createElement("td");
    tdOutcome.className = "audit-cell";
    const outcome = String(r.outcome || "success").toLowerCase();
    const pill = document.createElement("span");
    pill.className = `audit-outcome audit-outcome--${outcome}`;
    pill.textContent = outcome;
    tdOutcome.appendChild(pill);
    tr.appendChild(tdOutcome);

    // Client IP
    const tdIp = document.createElement("td");
    tdIp.className = "audit-cell audit-cell--mono";
    tdIp.textContent = ip;
    tr.appendChild(tdIp);

    const open = () => openDetail(r);
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        open();
      }
    });

    tbody.appendChild(tr);
  });
}

function renderPager(meta) {
  const host = el("auditPager");
  if (!host) return;
  host.innerHTML = "";
  const next = meta && meta.next_cursor;

  const info = document.createElement("span");
  info.className = "audit-pager-info";
  info.textContent = `Page ${cursorIndex + 1}`;
  host.appendChild(info);

  const back = document.createElement("button");
  back.type = "button";
  back.className = "secondary audit-pager-btn";
  back.textContent = "Previous";
  back.disabled = cursorIndex === 0;
  back.addEventListener("click", () => {
    if (cursorIndex === 0) return;
    cursorIndex = Math.max(0, cursorIndex - 1);
    loadEntries();
  });

  const first = document.createElement("button");
  first.type = "button";
  first.className = "secondary audit-pager-btn";
  first.textContent = "First page";
  first.disabled = cursorIndex === 0;
  first.addEventListener("click", () => {
    cursorStack = [null];
    cursorIndex = 0;
    loadEntries();
  });

  const nxt = document.createElement("button");
  nxt.type = "button";
  nxt.className = "secondary audit-pager-btn";
  nxt.textContent = "Next";
  nxt.disabled = !next;
  nxt.addEventListener("click", () => {
    cursorStack = cursorStack.slice(0, cursorIndex + 1);
    cursorStack.push(next);
    cursorIndex += 1;
    loadEntries();
  });

  host.appendChild(back);
  host.appendChild(first);
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
    const cursor = cursorStack[cursorIndex];
    if (cursor) {
      params.before_ts = cursor.before_ts;
      params.before_id = cursor.before_id;
    }
    const res = await apiGet("/audit/api/entries", params);
    const rows = res.data || [];
    renderTable(rows);
    renderPager(res.meta || {});
    showAlert(
      rows.length
        ? `Showing ${rows.length} entr${rows.length === 1 ? "y" : "ies"}.`
        : "",
      "info",
    );
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

  el("auditApplyBtn")?.addEventListener("click", () => {
    cursorStack = [null];
    cursorIndex = 0;
    loadEntries();
  });
  el("auditResetBtn")?.addEventListener("click", () => {
    el("auditFilterAction").value = "";
    el("auditFilterActor").value = "";
    el("auditFilterOutcome").value = "";
    cursorStack = [null];
    cursorIndex = 0;
    loadEntries();
  });

  try {
    await Promise.all([loadActions(), loadStats(), loadEntries()]);
  } catch (e) {
    showAlert(e.message || "Failed to load audit page.", "error");
  }
});