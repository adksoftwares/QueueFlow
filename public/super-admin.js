const $ = (s) => document.querySelector(s);

let currentUser = null;
let currentPolicy = { allowAdditionalSuperAdmins: false };
let currentView = "overview";

const state = {
  accounts: { page: 1, q: "", role: "all", status: "all" },
  businesses: { page: 1, q: "", status: "all" },
  security: { page: 1, q: "", type: "all", success: "all" },
  audit: { page: 1, q: "", action: "all" }
};

async function api(url, opt = {}) {
  const r = await fetch(url, {
    ...opt,
    headers: { "Content-Type": "application/json", ...(opt.headers || {}) }
  });
  if (r.status === 401) {
    location.href = "/?expired=1";
    throw Error("Session expired");
  }
  const d = await r.json().catch(() => ({}));
  if (r.status === 403 && d.code === "PASSWORD_CHANGE_REQUIRED") {
    if (!$("#saForcePwDialog").open) $("#saForcePwDialog").showModal();
    throw Error(d.error || "Password change required");
  }
  if (!r.ok) throw Error(d.error || "Request failed");
  return d;
}

function esc(s = "") {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[c]));
}

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return esc(iso);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function fmtShortId(id) {
  if (!id) return "—";
  return id.length > 10 ? `${id.slice(0, 8)}…` : id;
}

function fmtDetails(raw) {
  if (!raw) return "—";
  try {
    const obj = JSON.parse(raw);
    if (obj && typeof obj === "object") {
      return Object.entries(obj)
        .map(([k, v]) => `${k}: ${v}`)
        .join(" · ");
    }
  } catch {
    // fallback to raw
  }
  return String(raw);
}

function eventBadgeClass(eventType, success) {
  if (!success) return "status-suspended";
  if (eventType === "logout" || eventType === "password_changed" || eventType === "password_reset_completed") {
    return "status-info";
  }
  if (eventType === "session_revoked" || eventType === "password_reset_requested") {
    return "status-warn";
  }
  return "status-active";
}

function showGlobalError(msg = "") {
  $("#saGlobalError").textContent = msg;
}

function showGlobalSuccess(msg = "") {
  const el = $("#saGlobalSuccess");
  if (el) el.textContent = msg;
}

function renderPager(elId, data, onPage) {
  const el = $(elId);
  if (!el) return;
  el.innerHTML = `
    <span class="muted">Showing page ${data.page} of ${data.totalPages} (${data.total} total)</span>
    <div class="row-btns">
      <button class="btn ghost small-btn" data-prev="1" type="button" ${data.page <= 1 ? "disabled" : ""}>← Prev</button>
      <button class="btn ghost small-btn" data-next="1" type="button" ${data.page >= data.totalPages ? "disabled" : ""}>Next →</button>
    </div>
  `;
  const prev = el.querySelector("[data-prev]");
  const next = el.querySelector("[data-next]");
  if (prev) prev.onclick = () => onPage(data.page - 1);
  if (next) next.onclick = () => onPage(data.page + 1);
}

const VIEW_META = {
  overview: ["Platform Overview", "System-wide accounts, businesses, sessions, and security telemetry."],
  accounts: ["Account Management", "Search, inspect, provision, suspend, reset passwords, and manage sessions."],
  businesses: ["Business Directory", "Inspect multi-tenant workspaces, plans, usage, and moderation status."],
  security: ["Security & Login Monitoring", "Live active sessions, failed attempts, and device/IP audit events."],
  audit: ["System Audit Logs", "Immutable record of sensitive Super Admin and platform actions."],
  mfa: ["MFA & Super Admin Security", "Configure TOTP two-factor authentication and rotate Super Admin credentials."]
};

function switchView(view, opts = {}) {
  const validView = VIEW_META[view] ? view : "overview";
  currentView = validView;
  if (!opts.skipHash && location.hash !== `#${validView}`) {
    history.replaceState(null, "", `#${validView}`);
  }
  if (!opts.preserveSuccess) {
    showGlobalSuccess("");
  }
  const [title, sub] = VIEW_META[validView];
  $("#saViewTitle").textContent = title;
  $("#saViewSubtitle").textContent = sub;

  document.querySelectorAll("#saNav [data-view]").forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.view === validView);
  });
  document.querySelectorAll(".sa-view").forEach((sec) => {
    sec.classList.toggle("hidden", sec.id !== `view-${validView}`);
  });
  return loadActiveView();
}

async function loadActiveView() {
  showGlobalError("");
  try {
    if (currentView === "overview") await loadOverview();
    else if (currentView === "accounts") await loadAccounts();
    else if (currentView === "businesses") await loadBusinesses();
    else if (currentView === "security") await loadSecurity();
    else if (currentView === "audit") await loadAudit();
    else if (currentView === "mfa") await loadMfaPanel();
  } catch (err) {
    showGlobalError(err.message);
  }
}

async function loadOverview() {
  $("#saMetricsGrid").innerHTML = '<p class="muted">Loading platform metrics…</p>';
  const d = await api("/api/super-admin/overview");
  currentPolicy = d.policy || currentPolicy;

  const roleSelect = $("#saNewAccountRole");
  if (roleSelect) {
    roleSelect.innerHTML = currentPolicy.allowAdditionalSuperAdmins
      ? '<option value="owner">Business Owner</option><option value="super_admin">Super Admin</option>'
      : '<option value="owner">Business Owner</option>';
  }

  const m = d.metrics;
  const kpis = [
    ["Total Accounts", m.total_accounts],
    ["Active Accounts", m.active_accounts],
    ["Suspended Accounts", m.suspended_accounts],
    ["Deleted / Deactivated", m.deleted_accounts],
    ["Logged-in Users", m.currently_logged_in],
    ["Active Sessions", m.active_sessions],
    ["Total Logins", m.total_logins],
    ["New Registrations (7d)", m.new_registrations_7d],
    ["Failed Logins (24h)", m.failed_logins_24h],
    ["Suspicious Events (24h)", m.suspicious_events_24h],
    ["Businesses (Active / Susp.)", `${m.active_businesses} / ${m.suspended_businesses}`],
    ["Tickets (Today / Total)", `${m.tickets_today} / ${m.tickets_total}`]
  ];

  $("#saMetricsGrid").innerHTML = kpis
    .map(
      ([label, val]) =>
        `<div class="sa-kpi"><small>${esc(label)}</small><b>${esc(val)}</b></div>`
    )
    .join("");

  $("#saLastRegistered").innerHTML = d.last_registered.length
    ? d.last_registered
        .map(
          (u) => `<div class="service-row row-flex sa-compact-row">
            <div class="sa-row-main">
              <b>${esc(u.name)}</b>
              <small class="block-meta">${esc(u.email)} · ${esc(u.role)}</small>
            </div>
            <span class="row-btns nowrap-btns">
              <span class="status status-${esc(u.status)}">${esc(u.status)}</span>
              <button class="btn ghost small-btn" data-open-account="${u.id}" type="button">Inspect</button>
            </span>
          </div>`
        )
        .join("")
    : '<p class="muted empty-inline">No accounts registered yet.</p>';

  $("#saRecentLogins").innerHTML = d.recent_logins.length
    ? d.recent_logins
        .map(
          (e) => `<div class="service-row sa-event-row">
            <div class="sa-event-top">
              <span class="status ${eventBadgeClass(e.event_type, e.success)}">${esc(e.event_type)}</span>
              <small class="sa-event-time">${fmtDate(e.created_at)}</small>
            </div>
            <div class="sa-event-meta">
              <span>${esc(e.email || e.user_name || "Unknown")}</span>
              <small>${esc(e.device_info || "")}</small>
            </div>
          </div>`
        )
        .join("")
    : '<p class="muted empty-inline">No login activity recorded yet.</p>';

  $("#saBusinessUsage").innerHTML = d.business_usage.length
    ? `<table>
        <tr><th>Business</th><th>Code</th><th>Owner</th><th>Plan</th><th>Tickets (Today/Total)</th><th>Services / Staff</th><th>Status</th><th></th></tr>
        ${d.business_usage
          .map(
            (b) => `<tr>
              <td><b>${esc(b.name)}</b><br><small class="muted">${esc(b.category || "")}</small></td>
              <td>${esc(b.public_code)}</td>
              <td>${esc(b.owner_name)}<br><small class="muted">${esc(b.owner_email)}</small></td>
              <td>${esc(b.plan || "starter")}</td>
              <td>${b.tickets_today} / ${b.tickets_total}</td>
              <td>${b.services_count} / ${b.staff_count}</td>
              <td><span class="status status-${esc(b.status)}">${esc(b.status)}</span></td>
              <td><button class="btn ghost small-btn" data-open-business="${b.id}" type="button">Manage</button></td>
            </tr>`
          )
          .join("")}
      </table>`
    : '<p class="muted empty-inline">No businesses created yet.</p>';
}

async function loadAccounts() {
  const s = state.accounts;
  const qs = new URLSearchParams({
    page: String(s.page),
    limit: "15",
    q: s.q,
    role: s.role,
    status: s.status
  });
  const d = await api(`/api/super-admin/accounts?${qs}`);

  $("#saAccountsTable").innerHTML = d.accounts.length
    ? `<table>
        <tr><th>Account</th><th>Role</th><th>Status</th><th>MFA</th><th>Activity</th><th>Last Login</th><th>Registered</th><th></th></tr>
        ${d.accounts
          .map(
            (a) => `<tr>
              <td><b>${esc(a.name)}</b><br><small class="muted">${esc(a.email)}</small></td>
              <td class="nowrap-cell">${esc(a.role)}</td>
              <td><span class="status status-${esc(a.status)}">${esc(a.status)}</span></td>
              <td class="nowrap-cell">${a.mfa_enabled ? "Enabled" : "Off"}</td>
              <td class="nowrap-cell"><small>${a.owned_businesses} biz · ${a.login_count} logins</small></td>
              <td class="nowrap-cell"><small>${fmtDate(a.last_login_at)}</small></td>
              <td class="nowrap-cell"><small>${fmtDate(a.created_at)}</small></td>
              <td><button class="btn ghost small-btn" data-open-account="${a.id}" type="button">Manage →</button></td>
            </tr>`
          )
          .join("")}
      </table>`
    : '<p class="muted empty-inline">No accounts match your filters.</p>';

  renderPager("#saAccountsPager", d, (p) => {
    state.accounts.page = p;
    loadAccounts();
  });
}

function renderPasswordResetPanel({ accountId, accountLabel, containerEl, msgEl, onComplete }) {
  if (!containerEl) return;
  containerEl.innerHTML = `
    <div class="sa-edit-card sa-reset-card">
      <div class="panel-head">
        <h3>Reset password · ${esc(accountLabel)}</h3>
      </div>
      <form class="inline-grid sa-temp-pw-form">
        <label>Set temporary password (6+ chars)
          <input name="new_password" type="password" minlength="6" placeholder="Enter temporary password" required>
        </label>
        <label class="checkbox-row">
          <input type="checkbox" name="force_change_on_login" checked>
          <span>Require password change on next login</span>
        </label>
        <div class="inline-submit">
          <button class="btn" type="submit">Save temporary password</button>
          <button class="btn ghost sa-gen-reset-link" type="button">Generate one-time reset link</button>
        </div>
      </form>
      <div class="sa-reset-link-out"></div>
    </div>
  `;

  const setLocalMsg = (txt, ok = false) => {
    if (!msgEl) return;
    msgEl.textContent = txt || "";
    msgEl.className = ok ? "success-msg" : "error";
  };

  containerEl.querySelector(".sa-temp-pw-form").onsubmit = async (e) => {
    e.preventDefault();
    setLocalMsg("");
    const fd = new FormData(e.target);
    try {
      await api(`/api/super-admin/accounts/${accountId}/reset-password`, {
        method: "POST",
        body: JSON.stringify({
          new_password: fd.get("new_password"),
          force_change_on_login: fd.get("force_change_on_login") === "on",
          revoke_sessions: true
        })
      });
      e.target.reset();
      setLocalMsg(`Temporary password updated for ${accountLabel}. Active sessions revoked.`, true);
      if (onComplete) onComplete();
    } catch (err) {
      setLocalMsg(err.message);
    }
  };

  containerEl.querySelector(".sa-gen-reset-link").onclick = async () => {
    setLocalMsg("");
    try {
      const r = await api(`/api/super-admin/accounts/${accountId}/reset-password`, {
        method: "POST",
        body: JSON.stringify({ force_change_on_login: true, revoke_sessions: true })
      });
      const fullLink = location.origin + r.resetPath;
      const out = containerEl.querySelector(".sa-reset-link-out");
      out.innerHTML = `
        <div class="my-token lookup-details sa-copy-box">
          <small>ONE-TIME SECURE PASSWORD RESET LINK (EXPIRES ${fmtDate(r.expiresAt)})</small>
          <p class="muted">Deliver this reset link securely to ${esc(accountLabel)}. It will not be shown again:</p>
          <code class="break-code">${esc(fullLink)}</code>
          <div class="mt-10">
            <button class="btn ghost small-btn sa-copy-link-btn" type="button">Copy reset link</button>
          </div>
        </div>
      `;
      out.querySelector(".sa-copy-link-btn").onclick = async (ev) => {
        try {
          await navigator.clipboard.writeText(fullLink);
          ev.target.textContent = "Copied!";
        } catch {
          setLocalMsg("Select and copy the link above.", true);
        }
      };
      if (onComplete) onComplete();
    } catch (err) {
      setLocalMsg(err.message);
    }
  };
}

async function openAccountDetail(id) {
  const d = await api(`/api/super-admin/accounts/${id}`);
  const a = d.account;
  const activeSessions = d.sessions.filter((s) => s.is_active);

  $("#saDetailContent").innerHTML = `
    <div class="modal-header-bar">
      <div>
        <p class="eyebrow">ACCOUNT DETAIL · ${esc(a.role.toUpperCase())} · ${esc(a.status.toUpperCase())}</p>
        <h2>${esc(a.name)}</h2>
        <p class="muted">${esc(a.email)} ${a.phone ? `· ${esc(a.phone)}` : ""}</p>
      </div>
      <button class="close" id="saDetailClose" type="button" aria-label="Close">×</button>
    </div>

    <div id="saDetailMsg" class="error"></div>
    <div id="saResetResult"></div>

    <div class="queue-stats four-col">
      <div><small>STATUS</small><b>${esc(a.status)}</b></div>
      <div><small>ACTIVE SESSIONS</small><b>${activeSessions.length}</b></div>
      <div><small>MFA</small><b>${a.mfa_enabled ? "On" : "Off"}</b></div>
      <div><small>FAILED LOGINS</small><b>${a.failed_login_count}</b></div>
    </div>

    <div class="ops-bar">
      <div class="ops-group">
        ${
          a.status === "active"
            ? `<button class="btn warn-ghost" id="saSuspendBtn" type="button">Suspend account</button>`
            : `<button class="btn" id="saActivateBtn" type="button">Reactivate account</button>`
        }
        <button class="btn ghost" id="saResetPwBtn" type="button">Reset password</button>
        <button class="btn ghost" id="saRevokeAllBtn" type="button">Revoke all sessions</button>
      </div>
      <div class="ops-group">
        ${
          a.status !== "deleted" && a.id !== currentUser.id
            ? `<button class="btn danger-ghost" id="saSoftDeleteBtn" type="button">Deactivate</button>`
            : ""
        }
      </div>
    </div>

    <form id="saEditAccountForm" class="inline-grid sa-edit-card">
      <label>Full name<input name="name" value="${esc(a.name)}" required></label>
      <label>Email address<input name="email" type="email" value="${esc(a.email)}" required></label>
      <label>Phone<input name="phone" value="${esc(a.phone || "")}"></label>
      <label>Suspension / deactivation note<input name="suspension_reason" value="${esc(a.suspension_reason || "")}" placeholder="Optional reason"></label>
      <label class="checkbox-row">
        <input type="checkbox" name="must_change_password" ${a.must_change_password ? "checked" : ""}>
        <span>Force password change on next login</span>
      </label>
      <label class="checkbox-row">
        <input type="checkbox" name="unlock">
        <span>Clear failed login lock</span>
      </label>
      <div class="inline-submit">
        <button class="btn" type="submit">Save account updates</button>
      </div>
    </form>

    <div class="panel-head"><h3>Account metadata</h3></div>
    <div class="settings-summary">
      <p class="service-row"><b>Account ID</b> <small>${esc(a.id)}</small></p>
      <p class="service-row"><b>Registered</b> <small>${fmtDate(a.created_at)}</small></p>
      <p class="service-row"><b>Last login</b> <small>${fmtDate(a.last_login_at)} ${a.last_login_ip ? `(${esc(a.last_login_ip)})` : ""}</small></p>
      <p class="service-row"><b>Privacy notice accepted</b> <small>${fmtDate(a.privacy_notice_accepted_at)}</small></p>
    </div>

    <div class="panel-head"><h3>Associated businesses (${d.businesses.length})</h3></div>
    ${
      d.businesses.length
        ? `<div class="table-wrap"><table>
            <tr><th>Business</th><th>Code</th><th>Role</th><th>Status</th><th>Tickets</th></tr>
            ${d.businesses
              .map(
                (b) => `<tr>
                  <td>${esc(b.name)}</td>
                  <td>${esc(b.public_code)}</td>
                  <td>${esc(b.access_role)}</td>
                  <td><span class="status status-${esc(b.status)}">${esc(b.status)}</span></td>
                  <td>${b.tickets_total}</td>
                </tr>`
              )
              .join("")}
          </table></div>`
        : '<p class="muted empty-inline">No businesses associated.</p>'
    }

    <div class="panel-head"><h3>Sessions (${d.sessions.length})</h3></div>
    ${
      d.sessions.length
        ? `<div class="table-wrap"><table>
            <tr><th>Device</th><th>IP</th><th>Last Seen</th><th>State</th><th></th></tr>
            ${d.sessions
              .map(
                (s) => `<tr>
                  <td>${esc(s.device_info || "Unknown")}</td>
                  <td>${esc(s.ip || "-")}</td>
                  <td><small>${fmtDate(s.last_seen_at)}</small></td>
                  <td>${
                    s.revoked_at
                      ? "Revoked"
                      : s.logout_at
                      ? "Logged out"
                      : s.is_active
                      ? "Active"
                      : "Expired"
                  }</td>
                  <td>${
                    s.is_active
                      ? `<button class="btn ghost small-btn" data-revoke-sid="${esc(s.sid)}" type="button">Revoke</button>`
                      : ""
                  }</td>
                </tr>`
              )
              .join("")}
          </table></div>`
        : '<p class="muted empty-inline">No sessions recorded.</p>'
    }

    <div class="panel-head"><h3>Login &amp; security history</h3></div>
    ${
      d.login_history.length
        ? `<div class="table-wrap"><table>
            <tr><th>Time</th><th>Event</th><th>IP</th><th>Device</th></tr>
            ${d.login_history
              .slice(0, 15)
              .map(
                (l) => `<tr>
                  <td><small>${fmtDate(l.created_at)}</small></td>
                  <td><span class="status ${l.success ? "status-active" : "status-suspended"}">${esc(l.event_type)}</span></td>
                  <td>${esc(l.ip || "-")}</td>
                  <td>${esc(l.device_info || "-")}</td>
                </tr>`
              )
              .join("")}
          </table></div>`
        : '<p class="muted empty-inline">No login events recorded.</p>'
    }

    ${
      a.id !== currentUser.id
        ? `<div class="danger-zone">
            <div>
              <strong>Permanent deletion</strong>
              <p class="muted">Type <code>${esc(a.email)}</code> to permanently delete this account and all businesses they own.</p>
              <input id="saPermDeleteConfirm" placeholder="${esc(a.email)}" class="danger-input">
            </div>
            <button class="btn danger" id="saPermDeleteBtn" type="button">Permanently delete</button>
          </div>`
        : ""
    }
  `;

  if (!$("#saDetailDialog").open) $("#saDetailDialog").showModal();
  $("#saDetailClose").onclick = () => $("#saDetailDialog").close();

  const setMsg = (msg, isSuccess = false) => {
    const el = $("#saDetailMsg");
    el.className = isSuccess ? "success-msg" : "error";
    el.textContent = msg;
  };

  $("#saEditAccountForm").onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api(`/api/super-admin/accounts/${a.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          name: fd.get("name"),
          email: fd.get("email"),
          phone: fd.get("phone"),
          suspension_reason: fd.get("suspension_reason"),
          must_change_password: fd.get("must_change_password") === "on",
          unlock: fd.get("unlock") === "on"
        })
      });
      await openAccountDetail(a.id);
      loadActiveView();
    } catch (err) {
      setMsg(err.message);
    }
  };

  if ($("#saSuspendBtn")) {
    $("#saSuspendBtn").onclick = async () => {
      try {
        const reason = $("#saEditAccountForm input[name='suspension_reason']")?.value || "";
        await api(`/api/super-admin/accounts/${a.id}`, {
          method: "PATCH",
          body: JSON.stringify({ status: "suspended", suspension_reason: reason })
        });
        await openAccountDetail(a.id);
        loadActiveView();
      } catch (err) {
        setMsg(err.message);
      }
    };
  }

  if ($("#saActivateBtn")) {
    $("#saActivateBtn").onclick = async () => {
      try {
        await api(`/api/super-admin/accounts/${a.id}`, {
          method: "PATCH",
          body: JSON.stringify({ status: "active", unlock: true })
        });
        await openAccountDetail(a.id);
        loadActiveView();
      } catch (err) {
        setMsg(err.message);
      }
    };
  }

  if ($("#saSoftDeleteBtn")) {
    $("#saSoftDeleteBtn").onclick = async () => {
      try {
        await api(`/api/super-admin/accounts/${a.id}`, {
          method: "PATCH",
          body: JSON.stringify({ status: "deleted" })
        });
        await openAccountDetail(a.id);
        loadActiveView();
      } catch (err) {
        setMsg(err.message);
      }
    };
  }

  $("#saResetPwBtn").onclick = () => {
    renderPasswordResetPanel({
      accountId: a.id,
      accountLabel: a.email,
      containerEl: $("#saResetResult"),
      msgEl: $("#saDetailMsg"),
      onComplete: () => loadActiveView()
    });
  };

  $("#saRevokeAllBtn").onclick = async () => {
    try {
      const r = await api(`/api/super-admin/accounts/${a.id}/revoke-sessions`, {
        method: "POST",
        body: JSON.stringify({})
      });
      await openAccountDetail(a.id);
      setMsg(`Revoked ${r.revoked} session(s).`, true);
      loadActiveView();
    } catch (err) {
      setMsg(err.message);
    }
  };

  $("#saDetailContent").querySelectorAll("[data-revoke-sid]").forEach((btn) => {
    btn.onclick = async () => {
      try {
        await api(`/api/super-admin/accounts/${a.id}/revoke-sessions`, {
          method: "POST",
          body: JSON.stringify({ sid: btn.dataset.revokeSid })
        });
        await openAccountDetail(a.id);
        loadActiveView();
      } catch (err) {
        setMsg(err.message);
      }
    };
  });

  if ($("#saPermDeleteBtn")) {
    $("#saPermDeleteBtn").onclick = async () => {
      try {
        const confirmEmail = $("#saPermDeleteConfirm").value;
        await api(`/api/super-admin/accounts/${a.id}`, {
          method: "DELETE",
          body: JSON.stringify({ confirmEmail })
        });
        $("#saDetailDialog").close();
        loadActiveView();
      } catch (err) {
        setMsg(err.message);
      }
    };
  }
}

async function loadBusinesses() {
  const s = state.businesses;
  const qs = new URLSearchParams({
    page: String(s.page),
    limit: "15",
    q: s.q,
    status: s.status
  });
  const d = await api(`/api/super-admin/businesses?${qs}`);

  $("#saBusinessesTable").innerHTML = d.businesses.length
    ? `<table>
        <tr><th>Business</th><th>Code</th><th>Owner</th><th>Plan</th><th>Usage</th><th>Status</th><th>Created</th><th></th></tr>
        ${d.businesses
          .map(
            (b) => `<tr>
              <td><b>${esc(b.name)}</b><br><small class="muted">${esc(b.category || "")}</small></td>
              <td>${esc(b.public_code)}</td>
              <td>${esc(b.owner_name)}<br><small class="muted">${esc(b.owner_email)}</small></td>
              <td>${esc(b.plan || "starter")}</td>
              <td>${b.tickets_today} today · ${b.tickets_total} total</td>
              <td><span class="status status-${esc(b.status)}">${esc(b.status)}</span></td>
              <td><small>${fmtDate(b.created_at)}</small></td>
              <td><button class="btn ghost small-btn" data-open-business="${b.id}" type="button">Manage →</button></td>
            </tr>`
          )
          .join("")}
      </table>`
    : '<p class="muted empty-inline">No businesses match your filters.</p>';

  renderPager("#saBusinessesPager", d, (p) => {
    state.businesses.page = p;
    loadBusinesses();
  });
}

async function openBusinessDetail(id) {
  const d = await api(`/api/super-admin/businesses/${id}`);
  const b = d.business;

  $("#saDetailContent").innerHTML = `
    <div class="modal-header-bar">
      <div>
        <p class="eyebrow">TENANT WORKSPACE · ${esc(b.public_code)} · ${esc(b.status.toUpperCase())}</p>
        <h2>${esc(b.name)}</h2>
        <p class="muted">Owner: ${esc(b.owner_name)} (${esc(b.owner_email)}) · Registered ${fmtDate(b.created_at)}</p>
      </div>
      <button class="close" id="saDetailClose" type="button" aria-label="Close">×</button>
    </div>

    <div id="saBizMsg" class="error"></div>
    <div id="saBizResetResult"></div>

    <div class="queue-stats four-col">
      <div><small>LOCATIONS</small><b>${d.locations.length}</b></div>
      <div><small>SERVICES</small><b>${d.services.length}</b></div>
      <div><small>STAFF</small><b>${d.staff.length}</b></div>
      <div><small>PLAN</small><b>${esc(b.plan || "starter")}</b></div>
    </div>

    <form id="saEditBizForm" class="inline-grid sa-edit-card">
      <label>Status
        <select name="status">
          <option value="active" ${b.status === "active" ? "selected" : ""}>Active</option>
          <option value="paused" ${b.status === "paused" ? "selected" : ""}>Paused</option>
          <option value="suspended" ${b.status === "suspended" ? "selected" : ""}>Suspended</option>
        </select>
      </label>
      <label>Plan
        <select name="plan">
          <option value="starter" ${(b.plan || "starter") === "starter" ? "selected" : ""}>Starter</option>
          <option value="pro" ${b.plan === "pro" ? "selected" : ""}>Pro</option>
          <option value="enterprise" ${b.plan === "enterprise" ? "selected" : ""}>Enterprise</option>
        </select>
      </label>
      <label class="full-span">Suspension reason (if suspended)
        <input name="suspension_reason" value="${esc(b.suspension_reason || "")}" placeholder="Policy or billing note">
      </label>
      <div class="inline-submit">
        <button class="btn" type="submit">Update business status &amp; plan</button>
        <button class="btn ghost" type="button" id="saBizResetPwBtn">Reset owner password</button>
        <button class="btn ghost" type="button" data-open-account="${b.owner_id}">Inspect owner account</button>
      </div>
    </form>

    <div class="panel-head"><h3>Recent tickets (${d.recent_tickets.length})</h3></div>
    ${
      d.recent_tickets.length
        ? `<div class="table-wrap"><table>
            <tr><th>Token</th><th>Customer</th><th>Status</th><th>Date</th></tr>
            ${d.recent_tickets
              .slice(0, 15)
              .map(
                (t) => `<tr>
                  <td><b>${esc(t.token)}</b></td>
                  <td>${esc(t.customer_name)}</td>
                  <td><span class="status-tag">${esc(t.status)}</span></td>
                  <td class="nowrap-cell"><small>${esc(t.queue_date)}</small></td>
                </tr>`
              )
              .join("")}
          </table></div>`
        : '<p class="muted empty-inline">No tickets yet.</p>'
    }
  `;

  if (!$("#saDetailDialog").open) $("#saDetailDialog").showModal();
  $("#saDetailClose").onclick = () => $("#saDetailDialog").close();

  $("#saBizResetPwBtn").onclick = () => {
    renderPasswordResetPanel({
      accountId: b.owner_id,
      accountLabel: b.owner_email,
      containerEl: $("#saBizResetResult"),
      msgEl: $("#saBizMsg"),
      onComplete: () => loadActiveView()
    });
  };

  $("#saEditBizForm").onsubmit = async (e) => {
    e.preventDefault();
    const o = Object.fromEntries(new FormData(e.target));
    try {
      await api(`/api/super-admin/businesses/${b.id}`, {
        method: "PATCH",
        body: JSON.stringify(o)
      });
      await openBusinessDetail(b.id);
      loadActiveView();
    } catch (err) {
      $("#saBizMsg").textContent = err.message;
    }
  };
}

async function loadSecurity() {
  const [sessData, secData] = await Promise.all([
    api("/api/super-admin/sessions"),
    api(
      `/api/super-admin/security-events?${new URLSearchParams({
        page: String(state.security.page),
        limit: "20",
        q: state.security.q,
        type: state.security.type,
        success: state.security.success
      })}`
    )
  ]);

  $("#saSessionsTable").innerHTML = sessData.sessions.length
    ? `<table>
        <tr><th>User</th><th>Role</th><th>IP</th><th>Device</th><th>Last Active</th><th></th></tr>
        ${sessData.sessions
          .map(
            (s) => `<tr>
              <td><b>${esc(s.user_name)}</b><br><small class="muted">${esc(s.user_email)}</small></td>
              <td>${esc(s.user_role)}</td>
              <td>${esc(s.ip || "-")}</td>
              <td>${esc(s.device_info || "-")}</td>
              <td><small>${fmtDate(s.last_seen_at)}</small></td>
              <td><button class="btn ghost small-btn" data-force-logout="${esc(s.user_id)}" data-sid="${esc(s.sid)}" type="button">Revoke</button></td>
            </tr>`
          )
          .join("")}
      </table>`
    : '<p class="muted empty-inline">No active sessions.</p>';

  $("#saSecurityTable").innerHTML = secData.events.length
    ? `<table>
        <tr><th>Time</th><th>Event</th><th>Email</th><th>IP</th><th>Device</th><th>Details</th></tr>
        ${secData.events
          .map(
            (e) => `<tr>
              <td class="nowrap-cell"><small>${fmtDate(e.created_at)}</small></td>
              <td><span class="status ${eventBadgeClass(e.event_type, e.success)}">${esc(e.event_type)}</span></td>
              <td>${esc(e.email || "-")}</td>
              <td>${esc(e.ip || "-")}</td>
              <td>${esc(e.device_info || "-")}</td>
              <td class="details-cell"><small>${esc(e.details || "")}</small></td>
            </tr>`
          )
          .join("")}
      </table>`
    : '<p class="muted empty-inline">No security events match your filters.</p>';

  renderPager("#saSecurityPager", secData, (p) => {
    state.security.page = p;
    loadSecurity();
  });
}

async function loadAudit() {
  const s = state.audit;
  const qs = new URLSearchParams({
    page: String(s.page),
    limit: "25",
    q: s.q,
    action: s.action
  });
  const d = await api(`/api/super-admin/audit-logs?${qs}`);

  $("#saAuditTable").innerHTML = d.logs.length
    ? `<table>
        <tr><th>Time</th><th>Actor</th><th>Action</th><th>Entity</th><th>IP</th><th>Details</th></tr>
        ${d.logs
          .map(
            (l) => `<tr>
              <td class="nowrap-cell"><small>${fmtDate(l.created_at)}</small></td>
              <td>${esc(l.user_email || fmtShortId(l.user_id))}<br><small class="muted">${esc(l.actor_role || "-")}</small></td>
              <td class="nowrap-cell"><code>${esc(l.action)}</code></td>
              <td class="nowrap-cell" title="${esc(l.entity_id || "")}"><small>${esc(fmtShortId(l.entity_id))}</small></td>
              <td class="nowrap-cell">${esc(l.ip || "-")}</td>
              <td class="details-cell"><small>${esc(fmtDetails(l.details))}</small></td>
            </tr>`
          )
          .join("")}
      </table>`
    : '<p class="muted empty-inline">No audit logs found.</p>';

  renderPager("#saAuditPager", d, (p) => {
    state.audit.page = p;
    loadAudit();
  });
}

async function loadMfaPanel() {
  const me = (await api("/api/auth/me")).user;
  currentUser = me;
  $("#saMfaStatus").innerHTML = me.mfa_enabled
    ? `<div class="sa-notice">
        <strong>TOTP MFA is enabled</strong> on ${esc(me.email)}.
        <div class="row-btns mt-10">
          <button class="btn ghost small-btn" id="saStartMfaRotate" type="button">Re-enroll / Rotate MFA</button>
          <button class="btn danger small-btn" id="saOpenDisableMfa" type="button">Disable MFA</button>
        </div>
      </div>`
    : `<div class="sa-notice">
        <strong>MFA is not yet enrolled.</strong> Enroll an authenticator app (Google Authenticator, 1Password, Authy) to protect this Super Admin account.
        <div class="mt-10">
          <button class="btn small-btn" id="saStartMfaEnroll" type="button">Enable TOTP MFA →</button>
        </div>
      </div>`;

  $("#saMfaSetupArea").innerHTML = "";

  const startBtn = $("#saStartMfaEnroll") || $("#saStartMfaRotate");
  if (startBtn) {
    startBtn.onclick = async () => {
      const setup = await api("/api/auth/mfa/setup", { method: "POST" });
      $("#saMfaSetupArea").innerHTML = `
        <div class="sa-edit-card">
          <p><strong>1. Add this key to your authenticator app:</strong></p>
          <p>Secret Key: <code>${esc(setup.secret)}</code></p>
          <p>OTPAuth URI: <code class="break-code">${esc(setup.otpauthUri)}</code></p>
          <form id="saMfaConfirmForm" class="lookup-form">
            <input name="code" placeholder="Enter 6-digit code" required>
            <button class="btn" type="submit">Verify &amp; Activate MFA</button>
          </form>
          <div id="saRecoveryOut"></div>
        </div>
      `;
      $("#saMfaConfirmForm").onsubmit = async (e) => {
        e.preventDefault();
        const code = new FormData(e.target).get("code");
        try {
          const res = await api("/api/auth/mfa/confirm", {
            method: "POST",
            body: JSON.stringify({ code })
          });
          $("#saRecoveryOut").innerHTML = `<div class="my-token lookup-details">
            <small>MFA ACTIVATED — SAVE THESE ONE-TIME RECOVERY CODES</small>
            <p>${res.recoveryCodes.map((c) => `<code>${esc(c)}</code>`).join(" · ")}</p>
          </div>`;
          loadMfaPanel();
        } catch (err) {
          showGlobalError(err.message);
        }
      };
    };
  }

  if ($("#saOpenDisableMfa")) {
    $("#saOpenDisableMfa").onclick = () => {
      $("#saMfaSetupArea").innerHTML = `
        <form id="saMfaDisableForm" class="inline-grid sa-edit-card">
          <label>Confirm password<input name="password" type="password" required></label>
          <label>Current 6-digit TOTP code<input name="code" required></label>
          <div class="inline-submit">
            <button class="btn danger" type="submit">Confirm disable MFA</button>
          </div>
        </form>
      `;
      $("#saMfaDisableForm").onsubmit = async (e) => {
        e.preventDefault();
        try {
          await api("/api/auth/mfa/disable", {
            method: "POST",
            body: JSON.stringify(Object.fromEntries(new FormData(e.target)))
          });
          loadMfaPanel();
        } catch (err) {
          showGlobalError(err.message);
        }
      };
    };
  }
}

// Event bindings
document.querySelectorAll("#saNav [data-view]").forEach((btn) => {
  btn.onclick = () => switchView(btn.dataset.view);
});
$("#saRefreshBtn").onclick = () => loadActiveView();
async function handleLogout() {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } finally {
    location.href = "/";
  }
}

$("#saLogout").onclick = handleLogout;
if ($("#saTopLogout")) $("#saTopLogout").onclick = handleLogout;

$("#saNewAccountRole").onchange = (e) => {
  const bizField = $("#saCreateBizField");
  if (bizField) bizField.classList.toggle("hidden", e.target.value !== "owner");
};

$("#saNewAccountBtn").onclick = () => {
  $("#saCreateAccountError").textContent = "";
  const bizField = $("#saCreateBizField");
  if (bizField) {
    bizField.classList.toggle("hidden", $("#saNewAccountRole").value !== "owner");
  }
  $("#saCreateAccountDialog").showModal();
};
$("#saCreateAccountClose").onclick = () => $("#saCreateAccountDialog").close();
$("#saCreateAccountForm").onsubmit = async (e) => {
  e.preventDefault();
  $("#saCreateAccountError").textContent = "";
  const fd = new FormData(e.target);
  try {
    const res = await api("/api/super-admin/accounts", {
      method: "POST",
      body: JSON.stringify({
        name: fd.get("name"),
        email: fd.get("email"),
        phone: fd.get("phone"),
        role: fd.get("role"),
        business_name: fd.get("business_name"),
        password: fd.get("password"),
        must_change_password: fd.get("must_change_password") === "on"
      })
    });
    $("#saCreateAccountDialog").close();
    e.target.reset();

    state.accounts = { page: 1, q: "", role: "all", status: "all" };
    if ($("#accSearch")) $("#accSearch").value = "";
    if ($("#accRoleFilter")) $("#accRoleFilter").value = "all";
    if ($("#accStatusFilter")) $("#accStatusFilter").value = "all";

    const emailCreated = res.account?.email || "";
    if (res.business && currentView === "businesses") {
      showGlobalSuccess(
        `Account (${emailCreated}) and business "${res.business.name}" created.`
      );
      await loadBusinesses();
    } else {
      showGlobalSuccess(
        res.business
          ? `Account (${emailCreated}) and business "${res.business.name}" created.`
          : `Account created for ${emailCreated}.`
      );
      await switchView("accounts", { preserveSuccess: true });
    }
  } catch (err) {
    $("#saCreateAccountError").textContent = err.message;
  }
};

$("#saChangePwForm").onsubmit = async (e) => {
  e.preventDefault();
  $("#saPwMsg").textContent = "";
  try {
    await api("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify(Object.fromEntries(new FormData(e.target)))
    });
    e.target.reset();
    $("#saPwMsg").textContent = "Password updated.";
  } catch (err) {
    $("#saPwMsg").textContent = err.message;
  }
};

$("#saForcePwForm").onsubmit = async (e) => {
  e.preventDefault();
  $("#saForcePwError").textContent = "";
  try {
    await api("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify(Object.fromEntries(new FormData(e.target)))
    });
    $("#saForcePwDialog").close();
    e.target.reset();
    loadActiveView();
  } catch (err) {
    $("#saForcePwError").textContent = err.message;
  }
};

// Filters
$("#accSearch").oninput = (e) => {
  state.accounts.q = e.target.value;
  state.accounts.page = 1;
  loadAccounts();
};
$("#accRoleFilter").onchange = (e) => {
  state.accounts.role = e.target.value;
  state.accounts.page = 1;
  loadAccounts();
};
$("#accStatusFilter").onchange = (e) => {
  state.accounts.status = e.target.value;
  state.accounts.page = 1;
  loadAccounts();
};

$("#bizSearch").oninput = (e) => {
  state.businesses.q = e.target.value;
  state.businesses.page = 1;
  loadBusinesses();
};
$("#bizStatusFilter").onchange = (e) => {
  state.businesses.status = e.target.value;
  state.businesses.page = 1;
  loadBusinesses();
};

$("#secSearch").oninput = (e) => {
  state.security.q = e.target.value;
  state.security.page = 1;
  loadSecurity();
};
$("#secTypeFilter").onchange = (e) => {
  state.security.type = e.target.value;
  state.security.page = 1;
  loadSecurity();
};
$("#secSuccessFilter").onchange = (e) => {
  state.security.success = e.target.value;
  state.security.page = 1;
  loadSecurity();
};

$("#audSearch").oninput = (e) => {
  state.audit.q = e.target.value;
  state.audit.page = 1;
  loadAudit();
};
$("#audActionFilter").onchange = (e) => {
  state.audit.action = e.target.value;
  state.audit.page = 1;
  loadAudit();
};

document.addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;
  try {
    if (btn.dataset.openAccount) {
      await openAccountDetail(btn.dataset.openAccount);
    } else if (btn.dataset.openBusiness) {
      await openBusinessDetail(btn.dataset.openBusiness);
    } else if (btn.dataset.forceLogout) {
      await api(`/api/super-admin/accounts/${btn.dataset.forceLogout}/revoke-sessions`, {
        method: "POST",
        body: JSON.stringify({ sid: btn.dataset.sid })
      });
      loadSecurity();
    }
  } catch (err) {
    showGlobalError(err.message);
  }
});

async function init() {
  const meResp = await api("/api/auth/me");
  if (!meResp.user) {
    location.href = "/?expired=1";
    return;
  }
  if (meResp.user.role !== "super_admin") {
    location.href = "/dashboard.html";
    return;
  }
  currentUser = meResp.user;
  $("#saAdminEmail").textContent = currentUser.email;
  if (meResp.mustChangePassword) {
    $("#saForcePwDialog").showModal();
    return;
  }
  const initialHash = location.hash ? location.hash.slice(1) : "overview";
  const initialView = VIEW_META[initialHash] ? initialHash : "overview";
  await switchView(initialView, { skipHash: !VIEW_META[initialHash] });
}

init().catch((err) => {
  showGlobalError(err?.message || "Failed to load Super Admin console.");
});
