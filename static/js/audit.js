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

/**
 * Compact human-readable summary of an audit entry's `detail` blob,
 * tailored to the action. Answers "what actually changed" without the
 * reader having to open the modal and parse JSON.
 *
 * Falls back to the first two scalar fields for unknown actions, and
 * returns an empty string when there is nothing useful to show.
 */
function describeEntry(r) {
  const d = r.detail || {};
  const action = String(r.action || "");
  const targetLabel = r.target_type
    ? `${r.target_type}${r.target_id ? " #" + r.target_id : ""}`
    : "";

  switch (action) {
    case "user.set_role":
      return `${d.username || targetLabel}: ${d.old_role || "?"} → ${d.new_role || "?"}`;
    case "user.create":
      return `Created ${d.username || "?"} (${d.role || "?"})${d.email ? ", " + d.email : ""}`;
    case "user.delete":
      return `Deleted ${d.username || targetLabel}`;
    case "user.reset_password":
      return `Reset password for ${d.username || targetLabel}`;
    case "user.reset_mfa":
      return `Reset MFA for ${d.username || targetLabel}`;
    case "user.lock":
      return d.duration_hours != null
        ? `Locked ${d.username || targetLabel} for ${d.duration_hours}h`
        : `Locked ${d.username || targetLabel}`;
    case "user.unlock":
      return `Unlocked ${d.username || targetLabel}`;
    case "login.success": {
      const flags = [];
      if (d.totp_enabled) flags.push("TOTP");
      if (d.email_otp_enabled) flags.push("email OTP");
      return flags.length ? `MFA: ${flags.join(" + ")}` : "No MFA";
    }
    case "login.failure": {
      const parts = [];
      if (d.reason) parts.push(d.reason);
      if (d.attempts != null) parts.push(`attempt ${d.attempts}`);
      if (d.stage) parts.push(`[${d.stage}]`);
      // The username the caller tried. Present when the caller supplied
      // one at all — not set for bare scanner traffic.
      if (d.username && d.username !== r.actor_username) {
        parts.push(`as "${d.username}"`);
      }
      return parts.join(" ");
    }
    case "logout":
      return "";
    case "password.change":
      return "Password changed";
    case "profile.update": {
      const parts = [];
      if (d.username_changed) {
        parts.push(d.old_username && d.new_username
          ? `username: ${d.old_username} → ${d.new_username}`
          : "username");
      }
      if (d.email_changed) {
        const oldE = d.old_email || "(none)";
        const newE = d.new_email || "(none)";
        parts.push(`email: ${oldE} → ${newE}`);
      }
      if (d.avatar_changed) parts.push("avatar");
      return parts.join("; ");
    }
    case "mfa.totp.enable":
      return d.reason ? `reason: ${d.reason}` : "TOTP enabled";
    case "mfa.totp.disable":
      return d.reason ? `reason: ${d.reason}` : "TOTP disabled";
    case "mfa.totp.setup_started":
      return "TOTP setup started";
    case "mfa.totp.qr":
      return d.reason ? `reason: ${d.reason}` : "";
    case "mfa.email.enable":
      return d.reason ? `reason: ${d.reason}` : "Email OTP enabled";
    case "mfa.email.disable":
      return d.reason ? `reason: ${d.reason}` : "Email OTP disabled";
    case "mfa.email.login_start":
      return d.reason || "";
    case "ssl.ca_regenerate":
      if (d.error) return `Failed: ${d.error}`;
      return d.common_name ? `Regenerated ${d.common_name}` : "Regenerated root CA";
    case "ssl.bypass.add":
      return d.pattern
        ? `${d.match_type || "?"}: ${d.pattern}${d.reason ? ` (${d.reason})` : ""}`
        : (d.reason || "");
    case "ssl.bypass.delete":
      return d.pattern ? `${d.match_type || "?"}: ${d.pattern}` : "";
    case "sensor.auth_failure":
      return d.reason ? `reason: ${d.reason}` : "";
    case "auth.unauthorized":
    case "auth.forbidden":
      return d.path || "";
    case "rate_limit.exceeded":
    case "csrf.failure":
    case "server.error":
      return d.path || "";
    case "request.rejected":
      return [d.path, d.reason].filter(Boolean).join(" — ");
    case "route.not_found":
      return d.path || "";
    case "ssl.ca.download": {
      if (d.reason) return `Failed: ${d.reason}`;
      const cn = d.common_name || "root CA";
      return d.valid_until
        ? `Downloaded ${cn}, exp ${String(d.valid_until).slice(0, 10)}`
        : `Downloaded ${cn}`;
    }
    case "audit.read": {
      const f = d.filters || {};
      // Only user-chosen filters are recorded now, so a simple join is
      // enough. Empty filters means the analyst opened the page with no
      // constraints — that's the "just viewing the trail" case.
      const parts = Object.entries(f).map(([k, v]) => `${k}=${v}`);
      return parts.length ? `Viewed trail — ${parts.join(", ")}` : "Viewed trail";
    }
  }

  // Unknown action: surface up to two scalar key=value pairs so the reader
  // gets *some* signal without opening the modal.
  if (d && typeof d === "object") {
    const parts = [];
    for (const [k, v] of Object.entries(d)) {
      if (v == null || v === "" || typeof v === "object") continue;
      parts.push(`${k}: ${v}`);
      if (parts.length >= 2) break;
    }
    return parts.join(", ");
  }
  return "";
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
    td.colSpan = 7; td.className = "empty"; td.textContent = "No audit entries match your filters.";
    tr.appendChild(td); tbody.appendChild(tr);
    return;
  }

  rows.forEach((r) => {
    const tr = document.createElement("tr");
    tr.className = "audit-row";
    tr.tabIndex = 0;
    tr.setAttribute("role", "button");

    const ts = fmtTs(r.ts);
    const target = r.target_type
      ? `${r.target_type}${r.target_id ? " #" + r.target_id : ""}`
      : "—";
    const ip = r.actor_ip || "—";

    // Timestamp
    const tdTs = document.createElement("td");
    tdTs.className = "audit-cell audit-cell--mono";
    tdTs.textContent = ts;
    tr.appendChild(tdTs);

    // Actor — four cases:
    //   1. actor_username present → the real identity
    //   2. actor_id but no username → user record exists but was deleted
    //      or the row predates the username column being populated
    //   3. no actor at all, action starts with "auth."/"csrf."/"rate_limit."/
    //      "route." → rejected before authentication; label as "anonymous"
    //   4. no actor, everything else → "system" (sensor, worker, timer)
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
      muted.title = "Account no longer in the directory";
      tdActor.appendChild(muted);
    } else {
      const action = String(r.action || "");
      const preAuth =
        action.startsWith("auth.") ||
        action.startsWith("csrf.") ||
        action.startsWith("rate_limit.") ||
        action.startsWith("route.") ||
        action.startsWith("request.");
      const label = preAuth ? "anonymous" : "system";
      const muted = document.createElement("span");
      muted.className = "audit-actor audit-actor--muted";
      muted.textContent = label;
      muted.title = preAuth
        ? "Request was rejected before authentication"
        : "No interactive user — emitted by a background process";
      tdActor.appendChild(muted);
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

    // Details — short human-readable summary derived from the JSON blob.
    // The modal still shows the full JSON for anything not covered here.
    const tdDetails = document.createElement("td");
    tdDetails.className = "audit-cell audit-cell--details";
    const summary = describeEntry(r);
    if (summary) {
      tdDetails.textContent = summary;
      tdDetails.title = summary;
    } else {
      tdDetails.textContent = "—";
      tdDetails.classList.add("audit-cell--muted");
    }
    tr.appendChild(tdDetails);

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
    const toEpoch = (id) => {
      const v = el(id)?.value;
      if (!v) return "";
      const ms = new Date(v).getTime();
      return Number.isFinite(ms) ? Math.floor(ms / 1000) : "";
    };
    const params = {
      action: el("auditFilterAction")?.value || "",
      actor: el("auditFilterActor")?.value?.trim() || "",
      actor_ip: el("auditFilterIp")?.value?.trim() || "",
      target_type: el("auditFilterTargetType")?.value || "",
      outcome: el("auditFilterOutcome")?.value || "",
      start_time: toEpoch("auditFilterStart"),
      end_time: toEpoch("auditFilterEnd"),
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
    [
      "auditFilterAction", "auditFilterActor", "auditFilterIp",
      "auditFilterTargetType", "auditFilterOutcome",
      "auditFilterStart", "auditFilterEnd",
    ].forEach((id) => { const n = el(id); if (n) n.value = ""; });
    document.querySelectorAll(".audit-preset-btn.is-active")
      .forEach((btn) => btn.classList.remove("is-active"));
    cursorStack = [null];
    cursorIndex = 0;
    loadEntries();
  });

  document.querySelectorAll(".audit-preset-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const hours = Number(btn.dataset.hours || "0");
      document.querySelectorAll(".audit-preset-btn.is-active")
        .forEach((b) => b.classList.remove("is-active"));

      if (hours === 0) {
        el("auditFilterStart").value = "";
        el("auditFilterEnd").value = "";
      } else {
        const now = Date.now();
        const start = new Date(now - hours * 3600 * 1000);
        const end = new Date(now);
        const toLocal = (d) => {
          const off = d.getTimezoneOffset();
          return new Date(d.getTime() - off * 60 * 1000).toISOString().slice(0, 19);
        };
        el("auditFilterStart").value = toLocal(start);
        el("auditFilterEnd").value = toLocal(end);
        btn.classList.add("is-active");
      }
      cursorStack = [null];
      cursorIndex = 0;
      loadEntries();
    });
  });

  try {
    await Promise.all([loadActions(), loadStats(), loadEntries()]);
  } catch (e) {
    showAlert(e.message || "Failed to load audit page.", "error");
  }
});