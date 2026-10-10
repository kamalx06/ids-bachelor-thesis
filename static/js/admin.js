function el(id) {
  return document.getElementById(id);
}

function getCsrfToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.getAttribute("content") : "";
}

function showAdminAlert(message, type = "info") {
  const box = el("adminAlert");
  if (!box) return;
  box.textContent = message || "";
  box.className = message ? `alert ${type}` : "";
}

async function api(path, { method = "GET", body } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = getCsrfToken();

  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg =
      data?.error?.message ||
      data?.error ||
      `Request failed: ${res.status}`;
    throw new Error(msg);
  }
  if (data && typeof data.success === "boolean") return data;
  return { success: true, data, meta: {} };
}

function _initialsDataUri(username) {
  // First char of username injected into an SVG data URI. Safe today
  // because USERNAME_RE in uni-srver.py limits usernames to [a-zA-Z0-9_-].
  // If that rule is ever loosened, XML-escape this value.
  const ch = (username || "?").slice(0, 1).toUpperCase();
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32">` +
    `<rect width="32" height="32" rx="16" fill="#1e293b"/>` +
    `<text x="16" y="21" text-anchor="middle" font-family="DM Sans, Arial, sans-serif" ` +
    `font-size="14" font-weight="600" fill="#94a3b8">${ch}</text>` +
    `</svg>`;
  return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
}

function setKpi(id, value) {
  const node = el(id);
  if (!node) return;
  node.textContent = value == null ? "—" : String(value);
}

function renderKpis(users, meta) {
  // Total comes from the API's pagination meta; per-role and MFA counts
  // are computed from the currently-loaded page.
  const total = Number(meta?.total);
  setKpi("kpiTotalUsers", Number.isFinite(total) ? total : (users?.length ?? "—"));

  if (!Array.isArray(users)) {
    ["kpiAdmins", "kpiSoc", "kpiMfa", "kpiLocked"].forEach((id) => setKpi(id, "—"));
    return;
  }

  const admins = users.filter((u) => (u.role || "").toLowerCase() === "admin").length;
  const soc = users.filter((u) => (u.role || "").toLowerCase() === "soc").length;
  const mfa = users.filter((u) => u.totp_enabled || u.email_otp_enabled).length;
  const locked = users.filter((u) => u.locked_until).length;

  setKpi("kpiAdmins", admins);
  setKpi("kpiSoc", soc);
  setKpi("kpiMfa", mfa);
  setKpi("kpiLocked", locked);
}

function avatarCell(u) {
  const wrap = document.createElement("div");
  wrap.className = "admin-user-cell";

  const img = document.createElement("img");
  // Empty alt + explicit class so a broken image never renders the
  // alt text as a two-line placeholder in the table.
  img.alt = "";
  img.className = "admin-user-avatar";
  img.loading = "lazy";

  // If the stored avatar file is missing (user removed it, path stale),
  // the browser fires onerror. Fall back to the initials SVG so the row
  // always renders cleanly.
  img.onerror = () => {
    img.onerror = null;
    img.src = _initialsDataUri(u.username);
  };

  if (u.avatar_url) {
    img.src = `${u.avatar_url}?v=${encodeURIComponent(String(u.id))}`;
  } else {
    img.src = _initialsDataUri(u.username);
  }

  const name = document.createElement("span");
  name.className = "admin-user-name";
  name.textContent = u.username;

  wrap.appendChild(img);
  wrap.appendChild(name);
  return wrap;
}

function renderUsers(users, meta) {
  const tbody = el("usersTbody");
  if (!tbody) return;
  tbody.innerHTML = "";

  renderKpis(users, meta);

  if (!users || users.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 7;
    td.className = "empty";
    td.textContent = "No users.";
    tr.appendChild(td);
    tbody.appendChild(tr);
    renderPager(meta);
    return;
  }

  for (const u of users) {
    const tr = document.createElement("tr");

    const tdId = document.createElement("td");
    tdId.textContent = String(u.id);

    const tdUser = document.createElement("td");
    tdUser.appendChild(avatarCell(u));

    const tdRole = document.createElement("td");
    const roleSel = document.createElement("select");
    roleSel.className = "admin-role-select";
    roleSel.innerHTML = `
      <option value="soc">SOC Analyst</option>
      <option value="admin">IT Administrator</option>
    `;
    roleSel.value = (u.role || "soc").toLowerCase();
    roleSel.addEventListener("change", async () => {
      try {
        await api(`/admin/api/users/${u.id}/set_role`, {
          method: "POST",
          body: { role: roleSel.value },
        });
        showAdminAlert("Role updated.", "success");
      } catch (e) {
        showAdminAlert(e.message, "error");
        roleSel.value = (u.role || "soc").toLowerCase();
      }
    });
    tdRole.appendChild(roleSel);

    const tdEmail = document.createElement("td");
    tdEmail.textContent = u.email || "-";

    const tdMfa = document.createElement("td");
    tdMfa.textContent =
      `${u.totp_enabled ? "TOTP" : ""}${
        u.totp_enabled && u.email_otp_enabled ? " + " : ""
      }${u.email_otp_enabled ? "Email OTP" : ""}` || "None";

    const tdLock = document.createElement("td");
    tdLock.textContent = u.locked_until
      ? `Locked until ${u.locked_until}`
      : u.failed_attempts
        ? `Attempts: ${u.failed_attempts}`
        : "-";

    const tdActions = document.createElement("td");
    const actionsWrap = document.createElement("div");
    actionsWrap.className = "admin-actions";

    const lockBtn = document.createElement("button");
    lockBtn.type = "button";
    lockBtn.className = "secondary";
    lockBtn.textContent = u.locked_until ? "Unlock" : "Lock";
    lockBtn.addEventListener("click", async () => {
      const action = u.locked_until ? "unlock" : "lock";
      const confirmText = `Type "${u.username}" to ${action} this account:`;
      const typed = prompt(confirmText) || "";
      if (typed !== u.username) return;

      const body = { locked: !u.locked_until };

      // When locking, ask how long. Default "8" preserves the old
      // fixed-duration behaviour for an operator who just hits Enter.
      // Cancelling the second prompt aborts the whole lock so a
      // half-typed flow never leaves the account in an unexpected state.
      if (!u.locked_until) {
        const raw = prompt(
          "Lock duration in hours:\n" +
          "  0.05 = 3 min    |   1 = 1 hour\n" +
          "  24 = 1 day      |   168 = 1 week\n" +
          "  720 = 30 days   |   8760 = 1 year",
          "8",
        );
        if (raw === null) return; // user cancelled
        const hours = Number(raw);
        if (!Number.isFinite(hours) || hours <= 0) {
          showAdminAlert("Invalid duration — enter a positive number of hours.", "error");
          return;
        }
        body.duration_hours = hours;
      }

      try {
        const res = await api(`/admin/api/users/${u.id}/set_lock`, {
          method: "POST",
          body,
        });
        showAdminAlert(`User ${action}ed.`, "success");
        await refreshUsers();
      } catch (e) {
        showAdminAlert(e.message, "error");
      }
    });

    const resetMfaBtn = document.createElement("button");
    resetMfaBtn.type = "button";
    resetMfaBtn.className = "secondary";
    resetMfaBtn.textContent = "Reset MFA";
    resetMfaBtn.addEventListener("click", async () => {
      const typed = prompt(`Type "${u.username}" to confirm MFA reset:`) || "";
      if (typed !== u.username) return;
      try {
        await api(`/admin/api/users/${u.id}/reset_mfa`, { method: "POST", body: {} });
        showAdminAlert("MFA reset.", "success");
        await refreshUsers();
      } catch (e) {
        showAdminAlert(e.message, "error");
      }
    });

    const resetPwBtn = document.createElement("button");
    resetPwBtn.type = "button";
    resetPwBtn.className = "secondary";
    resetPwBtn.textContent = "Reset PW";
    resetPwBtn.addEventListener("click", async () => {
      const pw = prompt("Enter a new temporary password (12-64 chars):");
      if (!pw) return;
      try {
        await api(`/admin/api/users/${u.id}/reset_password`, { method: "POST", body: { new_password: pw } });
        showAdminAlert("Password reset.", "success");
      } catch (e) {
        showAdminAlert(e.message, "error");
      }
    });

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "danger";
    delBtn.textContent = "Delete";
    delBtn.addEventListener("click", async () => {
      const typed = prompt(`Type "${u.username}" to permanently delete:`) || "";
      if (typed !== u.username) return;
      try {
        await api(`/admin/api/users/${u.id}`, { method: "DELETE" });
        showAdminAlert("User deleted.", "success");
        await refreshUsers();
      } catch (e) {
        showAdminAlert(e.message, "error");
      }
    });

    actionsWrap.appendChild(lockBtn);
    actionsWrap.appendChild(resetMfaBtn);
    actionsWrap.appendChild(resetPwBtn);
    actionsWrap.appendChild(delBtn);
    tdActions.appendChild(actionsWrap);

    tr.appendChild(tdId);
    tr.appendChild(tdUser);
    tr.appendChild(tdRole);
    tr.appendChild(tdEmail);
    tr.appendChild(tdMfa);
    tr.appendChild(tdLock);
    tr.appendChild(tdActions);
    tbody.appendChild(tr);
  }
  renderPager(meta);
}

function stateFromUI() {
  return {
    q: el("userSearch")?.value?.trim() || "",
    sort: el("userSort")?.value || "id",
    order: el("userOrder")?.value || "desc",
    page_size: Number(el("userPageSize")?.value || 25),
  };
}

let currentPage = 1;

function renderPager(meta = {}) {
  const host = el("usersPager");
  if (!host) return;
  const total = Number(meta.total || 0);
  const page = Number(meta.page || currentPage || 1);
  const pageSize = Number(meta.page_size || 25);
  const pages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)));

  host.innerHTML = "";
  const info = document.createElement("span");
  info.textContent = `Page ${page} / ${pages} (${total} users)`;
  info.style.marginRight = "12px";

  const prev = document.createElement("button");
  prev.type = "button";
  prev.className = "secondary admin-pager-btn";
  prev.textContent = "Prev";
  prev.disabled = page <= 1;
  prev.addEventListener("click", async () => {
    currentPage = Math.max(1, page - 1);
    await refreshUsers();
  });

  const next = document.createElement("button");
  next.type = "button";
  next.className = "secondary admin-pager-btn";
  next.textContent = "Next";
  next.disabled = page >= pages;
  next.addEventListener("click", async () => {
    currentPage = Math.min(pages, page + 1);
    await refreshUsers();
  });

  host.appendChild(info);
  host.appendChild(prev);
  host.appendChild(next);
}

async function refreshUsers() {
  const st = stateFromUI();
  const url = new URL("/admin/api/users", window.location.origin);
  url.searchParams.set("page", String(currentPage));
  url.searchParams.set("page_size", String(st.page_size));
  url.searchParams.set("q", st.q);
  url.searchParams.set("sort", st.sort);
  url.searchParams.set("order", st.order);

  const res = await api(url.toString());
  renderUsers(res.data || [], res.meta || {});
}

document.addEventListener("DOMContentLoaded", async () => {
  el("createUserBtn")?.addEventListener("click", async () => {
    try {
      const username = el("newUsername")?.value?.trim() || "";
      const email = el("newEmail")?.value?.trim() || "";
      const role = el("newRole")?.value || "soc";
      const password = el("newPassword")?.value || "";

      await api("/admin/api/users", { method: "POST", body: { username, email, role, password } });
      showAdminAlert("User created.", "success");
      el("newUsername").value = "";
      el("newEmail").value = "";
      el("newPassword").value = "";
      await refreshUsers();
    } catch (e) {
      showAdminAlert(e.message, "error");
    }
  });

  el("refreshUsersBtn")?.addEventListener("click", () => {
    refreshUsers().catch((e) => showAdminAlert(e.message, "error"));
  });

  el("applyFiltersBtn")?.addEventListener("click", () => {
    currentPage = 1;
    refreshUsers().catch((e) => showAdminAlert(e.message, "error"));
  });
  el("clearFiltersBtn")?.addEventListener("click", () => {
    currentPage = 1;
    if (el("userSearch")) el("userSearch").value = "";
    if (el("userSort")) el("userSort").value = "id";
    if (el("userOrder")) el("userOrder").value = "desc";
    if (el("userPageSize")) el("userPageSize").value = "25";
    refreshUsers().catch((e) => showAdminAlert(e.message, "error"));
  });
  el("userSearch")?.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    currentPage = 1;
    refreshUsers().catch((err) => showAdminAlert(err.message, "error"));
  });

  try {
    await refreshUsers();
  } catch (e) {
    showAdminAlert(e.message, "error");
  }
});

