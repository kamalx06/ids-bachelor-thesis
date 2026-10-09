function el(id) { return document.getElementById(id); }

function csrf() {
  const m = document.querySelector('meta[name="csrf-token"]');
  return m ? m.getAttribute("content") : "";
}

function showAlert(msg, type = "info") {
  const box = el("sslAlert");
  if (!box) return;
  box.textContent = msg || "";
  box.className = msg ? `alert ${type}` : "";
}

async function api(path, { method = "GET", body } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = csrf();
  const res = await fetch(path, {
    method, headers, credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.success === false) {
    throw new Error(data?.error?.message || data?.error || `HTTP ${res.status}`);
  }
  return data.data;
}

function fmtDate(v) {
  if (!v) return "—";
  const d = new Date(v);
  if (!Number.isFinite(d.getTime())) return "—";
  return d.toISOString().slice(0, 19).replace("T", " ");
}

async function refreshBypassSyncStatus() {
  const host = el("bypassSyncStatus");
  if (!host) return;
  try {
    const st = await api("/ssl/api/bypass/iptables-status");
    host.innerHTML = "";
    if (!st.root) {
      host.textContent =
        "Firewall sync: unavailable (the web process is not running as root). " +
        "The interceptor process will apply changes independently.";
      host.style.color = "#fcd34d";
      return;
    }
    const missing = st.missing || [];
    const stale = st.stale || [];
    if (missing.length === 0 && stale.length === 0) {
      host.textContent =
        `Firewall sync: OK — ${st.have.length} SNI rule(s) enforced at the iptables layer.`;
      host.style.color = "#a7f3d0";
    } else {
      const parts = [];
      if (missing.length) parts.push(`${missing.length} not yet installed (${missing.join(", ")})`);
      if (stale.length) parts.push(`${stale.length} stale in firewall (${stale.join(", ")})`);
      host.textContent = "Firewall sync: " + parts.join("; ") + ".";
      host.style.color = "#fcd34d";
    }
  } catch (e) {
    host.textContent = "Firewall sync: unable to read status.";
    host.style.color = "#fca5a5";
  }
}

async function loadStatus() {
  const s = await api("/ssl/api/status");
  el("sslEnabled").textContent = s.enabled ? "ENABLED" : "DISABLED";
  el("sslRunning").textContent = s.interceptor_running ? "RUNNING" : "STOPPED";
  el("sslCaPresent").textContent = s.ca_present ? "PRESENT" : "MISSING";
  el("sslPort").textContent = String(s.intercept_port);
}

async function loadCa() {
  const c = await api("/ssl/api/ca");
  if (!c) return;
  el("caCn").textContent = c.common_name || "—";
  el("caSerial").textContent = c.serial_hex || "—";
  el("caNotBefore").textContent = fmtDate(c.not_before);
  el("caNotAfter").textContent = fmtDate(c.not_after);
  el("caFingerprint").textContent = c.fingerprint_sha256 || "—";
}

async function loadBypass() {
  const rows = await api("/ssl/api/bypass");
  const tbody = el("bypassTbody");
  tbody.innerHTML = "";
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5; td.className = "empty"; td.textContent = "No bypass rules.";
    tr.appendChild(td); tbody.appendChild(tr);
    return;
  }
  for (const r of rows) {
    const tr = document.createElement("tr");
    [r.match_type, r.pattern, r.reason || "—", r.enabled ? "Yes" : "No"].forEach((v) => {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    });
    const tdActions = document.createElement("td");
    const del = document.createElement("button");
    del.type = "button";
    del.className = "danger";
    del.style.width = "auto";
    del.textContent = "Delete";
    del.addEventListener("click", async () => {
      if (!confirm(`Delete rule ${r.pattern}?`)) return;
      try {
        await api(`/ssl/api/bypass/${r.id}`, { method: "DELETE" });
        await loadBypass();
        await refreshBypassSyncStatus();
        showAlert("Rule deleted.", "success");
      } catch (e) { showAlert(e.message, "error"); }
    });
    tdActions.appendChild(del);
    tr.appendChild(tdActions);
    tbody.appendChild(tr);
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  el("regenerateCaBtn")?.addEventListener("click", async () => {
    if (!confirm("Regenerate the root CA? Every client that trusted the current CA will need to re-install it. Interceptor restart required.")) return;
    try {
      await api("/ssl/api/ca/regenerate", { method: "POST", body: {} });
      showAlert("New CA generated. Restart the supervisor for it to take effect.", "success");
      await loadCa();
    } catch (e) { showAlert(e.message, "error"); }
  });

  el("copyFingerprintBtn")?.addEventListener("click", async () => {
    const fp = (el("caFingerprint")?.textContent || "").trim();
    if (!fp || fp === "—") {
      showAlert("Fingerprint not available yet. Load the CA metadata first.", "error");
      return;
    }

    // Prefer the modern async clipboard API; fall back to a hidden
    // textarea + execCommand for non-secure contexts (older browsers,
    // plain http://localhost during development).
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(fp);
      } else {
        const ta = document.createElement("textarea");
        ta.value = fp;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      showAlert("SHA-256 fingerprint copied to clipboard.", "success");
    } catch (e) {
      showAlert("Could not copy — select the fingerprint manually from the table.", "error");
    }
  });

  el("addBypassBtn")?.addEventListener("click", async () => {
    const match_type = el("bpType").value;
    const pattern = el("bpPattern").value.trim();
    const reason = el("bpReason").value.trim();
    if (!pattern) { showAlert("Pattern required.", "error"); return; }
    try {
      await api("/ssl/api/bypass", { method: "POST", body: { match_type, pattern, reason } });
      el("bpPattern").value = "";
      el("bpReason").value = "";
      await loadBypass();
      await refreshBypassSyncStatus();
      showAlert(`Rule added for ${pattern}.`, "success");
    } catch (e) {
      showAlert(e.message, "error");
    }
  });

  try {
    await Promise.all([loadStatus(), loadCa(), loadBypass()]);
    await refreshBypassSyncStatus();
  } catch (e) {
    showAlert(e.message || "Failed to load SSL page.", "error");
  }

  // Re-check the sync state periodically so the page stays honest about
  // whether the firewall has caught up with the DB.
  setInterval(refreshBypassSyncStatus, 15000);
});