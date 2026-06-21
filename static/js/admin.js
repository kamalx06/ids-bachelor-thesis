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

function avatarCell(u) {
  const wrap = document.createElement("div");
  wrap.style.display = "flex";
  wrap.style.alignItems = "center";
  wrap.style.gap = "10px";

  const img = document.createElement("img");
  img.alt = "Profile picture";
  img.width = 28;
  img.height = 28;
  img.style.borderRadius = "999px";
  img.style.objectFit = "cover";
  img.style.border = "1px solid rgba(255,255,255,.12)";

  if (u.avatar_url) {
    const bust = `${u.avatar_url}?v=${encodeURIComponent(String(u.id))}`;
    img.src = bust;
  } else {
    img.src =
      "data:image/svg+xml;charset=utf-8," +
      encodeURIComponent(
        `<svg xmlns="http://www.w3.org/2000/svg" width="28" height="28"><rect width="28" height="28" rx="14" fill="#111827"/><text x="14" y="18" text-anchor="middle" font-family="Arial" font-size="14" fill="#9ca3af">${(u.username || "?").slice(0,1).toUpperCase()}</text></svg>`
      );
  }

  const name = document.createElement("span");
  name.textContent = u.username;

  wrap.appendChild(img);
  wrap.appendChild(name);
  return wrap;
}

function renderUsers(users, meta) {
  const tbody = el("usersTbody");
  if (!tbody) return;
  tbody.innerHTML = "";

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

    const lockBtn = document.createElement("button");
    lockBtn.type = "button";
    lockBtn.className = "secondary";
    lockBtn.textContent = u.locked_until ? "Unlock" : "Lock";
    lockBtn.style.width = "auto";
    lockBtn.style.marginRight = "8px";
    lockBtn.addEventListener("click", async () => {
      const action = u.locked_until ? "unlock" : "lock";
      const confirmText = `Type "${u.username}" to ${action} this account:`;
      const typed = prompt(confirmText) || "";
      if (typed !== u.username) return;
      try {
        await api(`/admin/api/users/${u.id}/set_lock`, {
          method: "POST",
          body: { locked: !u.locked_until },
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
    resetMfaBtn.style.width = "auto";
    resetMfaBtn.style.marginRight = "8px";
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
    resetPwBtn.style.width = "auto";
    resetPwBtn.style.marginRight = "8px";
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
    delBtn.style.width = "auto";
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

    tdActions.appendChild(lockBtn);
    tdActions.appendChild(resetMfaBtn);
    tdActions.appendChild(resetPwBtn);
    tdActions.appendChild(delBtn);

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
  prev.className = "secondary";
  prev.textContent = "Prev";
  prev.disabled = page <= 1;
  prev.style.width = "auto";
  prev.style.marginRight = "8px";
  prev.addEventListener("click", async () => {
    currentPage = Math.max(1, page - 1);
    await refreshUsers();
  });

  const next = document.createElement("button");
  next.type = "button";
  next.className = "secondary";
  next.textContent = "Next";
  next.disabled = page >= pages;
  next.style.width = "auto";
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

