const $ = (s) => document.querySelector(s);

let businesses = [];
let active = null;
let activeLocationId = "";
let activeTab = "queue";
let activeData = null;

const socket = io({ transports: ["websocket", "polling"] });
socket.on("connect", () => {
  if (active) socket.emit("join-business", active);
});
socket.on("session:revoked", () => {
  location.href = "/?expired=1";
});
socket.on("business:revoked", (payload) => {
  if (active && payload?.business_id === active) {
    active = null;
    activeLocationId = "";
    activeData = null;
    if ($("#manageDialog").open) $("#manageDialog").close();
    load().catch(() => {});
  }
});
socket.on("queue:update", (x) => {
  if (!active || (x.business_id && x.business_id !== active)) return;
  if (activeLocationId) {
    manage(active, activeLocationId, activeTab).catch(() => {});
    return;
  }
  if (activeData) {
    activeData.queue = x.tickets;
    activeData.appointments = x.appointments || activeData.appointments;
    activeData.recent_tickets = x.recent_tickets || activeData.recent_tickets;
    activeData.stats = x.stats;
    activeData.performance = x.performance || activeData.performance;
  }
  renderTabPanels();
  load().catch(() => {});
});

async function api(url, opt = {}) {
  const r = await fetch(url, {
    ...opt,
    headers:
      opt.body instanceof FormData
        ? opt.headers
        : { "Content-Type": "application/json", ...(opt.headers || {}) }
  });
  if (r.status === 401) {
    location.href = "/?expired=1";
    throw Error("Session expired");
  }
  const d = await r.json().catch(() => ({}));
  if (r.status === 403 && d.code === "PASSWORD_CHANGE_REQUIRED") {
    if ($("#forcePasswordDialog") && !$("#forcePasswordDialog").open) {
      $("#forcePasswordDialog").showModal();
    }
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

function showManageError(msg) {
  const el = $("#manageError");
  if (el) el.textContent = msg || "";
}

async function init() {
  const meResp = await api("/api/auth/me");
  const me = meResp.user;
  if (!me) {
    location.href = "/";
    return;
  }
  $("#welcomeName").textContent = me.name;
  $("#sideName").textContent = me.email;
  $("#accountEmail").textContent = `${me.email} (${me.role})`;
  const detectedTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  if (detectedTz && $("#businessTimezone")) {
    $("#businessTimezone").value = detectedTz;
  }
  if (me.role === "super_admin") {
    $("#adminLink").classList.remove("hidden");
  }
  if (meResp.mustChangePassword) {
    $("#forcePasswordDialog").showModal();
    return;
  }
  await load();
}

async function load() {
  const d = await api("/api/dashboard");
  businesses = d.businesses;
  $("#businessList").innerHTML = businesses.length
    ? businesses
        .map(
          (b) => `<article class="business-card">
            <div class="business-head">
              <div>
                <p class="eyebrow">${esc(b.category || "BUSINESS")} · CODE ${esc(b.public_code)} · ${esc(b.access_role || "owner")} · ${esc(b.timezone || "UTC")}</p>
                <h2>${esc(b.name)}</h2>
                <p>${esc(b.address || "Address not added")}</p>
              </div>
              <span class="status status-${esc(b.status)}">${esc(b.status)}</span>
            </div>
            <div class="business-stats five-col">
              <div><small>Waiting</small><b>${b.waiting}</b></div>
              <div><small>Called</small><b>${b.called || 0}</b></div>
              <div><small>Serving</small><b>${b.serving}</b></div>
              <div><small>Scheduled</small><b>${b.scheduled || 0}</b></div>
              <div><small>Completed today</small><b>${b.completed}</b></div>
            </div>
            <div class="business-actions">
              <button class="btn" data-manage="${b.id}" type="button">Open workspace →</button>
              <a class="btn ghost" target="_blank" href="/q/${encodeURIComponent(b.public_code)}">Public queue ↗</a>
              <button class="btn ghost" data-share="${b.id}" type="button">QR &amp; short link</button>
            </div>
          </article>`
        )
        .join("")
    : '<div class="empty">No business workspace yet. Add your first business to begin.</div>';

  document.querySelectorAll("[data-manage]").forEach((btn) => {
    btn.onclick = () => manage(btn.dataset.manage, "", "queue");
  });
  document.querySelectorAll("[data-share]").forEach((btn) => {
    btn.onclick = () => openShareDialog(btn.dataset.share);
  });
}

async function openShareDialog(businessId, preselectedLocId = "") {
  const b = businesses.find((x) => x.id === businessId) || activeData?.business;
  if (!b) return;

  let locations = [];
  if (activeData?.business?.id === businessId && Array.isArray(activeData.locations)) {
    locations = activeData.locations.filter((l) => l.is_active);
  } else {
    try {
      const detail = await api(`/api/businesses/${businessId}`);
      locations = (detail.locations || []).filter((l) => l.is_active);
    } catch {
      locations = [];
    }
  }

  let selectedLoc = preselectedLocId || "";
  const code = b.public_code;
  const encCode = encodeURIComponent(code);

  function buildShareUrls(locId) {
    const locSuffix = locId ? `?location_id=${encodeURIComponent(locId)}` : "";
    const shortUrl = `${location.origin}/q/${encCode}${locSuffix}`;
    const qrSvg = `/api/public/${encCode}/qr.svg${locSuffix}`;
    const dlSep = locSuffix ? "&" : "?";
    const pngDownload = `/api/public/${encCode}/qr.png${locSuffix}${dlSep}download=1`;
    const svgDownload = `/api/public/${encCode}/qr.svg${locSuffix}${dlSep}download=1`;
    return { shortUrl, qrSvg, pngDownload, svgDownload };
  }

  const urls = buildShareUrls(selectedLoc);

  $("#shareContent").innerHTML = `
    <div class="modal-header-bar">
      <div>
        <p class="eyebrow">SHARE PUBLIC QUEUE · CODE ${esc(code)}</p>
        <h2>${esc(b.name)}</h2>
      </div>
      <button class="close" id="shareClose" type="button" aria-label="Close">×</button>
    </div>

    ${
      locations.length
        ? `<label class="share-loc-label">Branch / location
            <select id="shareLocSelect">
              <option value="">All locations</option>
              ${locations
                .map(
                  (l) =>
                    `<option value="${l.id}" ${selectedLoc === l.id ? "selected" : ""}>${esc(
                      l.name
                    )}</option>`
                )
                .join("")}
            </select>
          </label>`
        : ""
    }

    <div class="qr-poster">
      <div class="qr-frame">
        <img id="shareQrImg" src="${esc(urls.qrSvg)}" alt="QR code for ${esc(b.name)}">
      </div>
      <p class="qr-caption"><b>${esc(b.name)}</b> · Scan to view live queue &amp; book token</p>
    </div>

    <div class="share-link-block">
      <label for="shareShortInput">Short public link</label>
      <div class="share-link-row">
        <input id="shareShortInput" type="text" readonly value="${esc(urls.shortUrl)}">
        <button class="btn" id="shareCopyBtn" type="button">Copy link</button>
      </div>
      <p id="shareStatusMsg" class="success-msg"></p>
    </div>

    <div class="share-actions-row">
      <a class="btn ghost" id="shareDlPng" href="${esc(urls.pngDownload)}" download>Download QR (PNG)</a>
      <a class="btn ghost" id="shareDlSvg" href="${esc(urls.svgDownload)}" download>Download QR (SVG)</a>
      <button class="btn ghost" id="shareNativeBtn" type="button">Share…</button>
      <a class="btn ghost" id="shareOpenPublic" target="_blank" href="${esc(urls.shortUrl)}">Open page ↗</a>
    </div>
  `;

  if (!$("#shareDialog").open) {
    $("#shareDialog").showModal();
  }
  $("#shareClose").onclick = () => $("#shareDialog").close();

  const updateShareTarget = (locId) => {
    selectedLoc = locId;
    const next = buildShareUrls(selectedLoc);
    $("#shareQrImg").src = next.qrSvg;
    $("#shareShortInput").value = next.shortUrl;
    $("#shareDlPng").href = next.pngDownload;
    $("#shareDlSvg").href = next.svgDownload;
    $("#shareOpenPublic").href = next.shortUrl;
    $("#shareStatusMsg").textContent = "";
  };

  if ($("#shareLocSelect")) {
    $("#shareLocSelect").onchange = (e) => updateShareTarget(e.target.value);
  }

  $("#shareCopyBtn").onclick = async () => {
    const val = $("#shareShortInput").value;
    try {
      await navigator.clipboard.writeText(val);
      $("#shareCopyBtn").textContent = "Copied!";
      $("#shareStatusMsg").textContent = "Short link copied to clipboard.";
      setTimeout(() => {
        if ($("#shareCopyBtn")) $("#shareCopyBtn").textContent = "Copy link";
      }, 2000);
    } catch {
      $("#shareShortInput").select();
      $("#shareStatusMsg").textContent = "Link selected — press Ctrl+C to copy.";
    }
  };

  $("#shareNativeBtn").onclick = async () => {
    const val = $("#shareShortInput").value;
    if (navigator.share) {
      try {
        await navigator.share({
          title: `${b.name} — Live Queue`,
          text: `Check live wait times or take a token for ${b.name}:`,
          url: val
        });
        return;
      } catch {
        // user cancelled or unavailable -> fallback to copy
      }
    }
    $("#shareCopyBtn").click();
  };
}

function ticketRow(t) {
  const staffList = (activeData?.staff || []).filter((s) => s.is_active);
  const metaParts = [t.service_name || "General", t.location_name].filter(Boolean);
  return `<div class="ticket-admin">
    <b>${esc(t.token)}</b>
    <div>
      <span>${esc(t.customer_name)}</span>
      <small class="block-meta">${esc(metaParts.join(" · "))}</small>
    </div>
    <select data-assign="${t.id}" aria-label="Assign staff">
      <option value="">Unassigned</option>
      ${staffList
        .map(
          (s) =>
            `<option value="${s.id}" ${t.staff_id === s.id ? "selected" : ""}>${esc(
              s.counter_label ? `${s.name} (${s.counter_label})` : s.name
            )}</option>`
        )
        .join("")}
    </select>
    <select data-status="${t.id}" aria-label="Ticket status">
      <option value="waiting" ${t.status === "waiting" ? "selected" : ""}>waiting</option>
      <option value="called" ${t.status === "called" ? "selected" : ""}>called</option>
      <option value="serving" ${t.status === "serving" ? "selected" : ""}>serving</option>
      <option value="completed">completed</option>
      <option value="no_show">no_show</option>
      <option value="cancelled">cancelled</option>
    </select>
  </div>`;
}

function appointmentRow(t) {
  const when = t.appointment_at ? new Date(t.appointment_at).toLocaleString() : "Scheduled";
  return `<div class="ticket-admin">
    <b>${esc(t.token)}</b>
    <div>
      <span>${esc(t.customer_name)}</span>
      <small class="block-meta">${esc(when)} · ${esc(t.service_name || "General")}</small>
    </div>
    <small>${esc(t.location_name || "Main")}</small>
    <span class="row-btns">
      <button class="btn ghost small-btn" data-checkin="${t.id}" type="button">Check in →</button>
      <button class="btn ghost small-btn" data-cancel-appt="${t.id}" type="button">Cancel</button>
    </span>
  </div>`;
}

function renderTabPanels() {
  if (!activeData) return;

  const statsEl = $("#modalStats");
  if (statsEl) {
    statsEl.innerHTML = `
      <div><small>WAITING</small><b>${activeData.stats.waiting}</b></div>
      <div><small>CALLED</small><b>${activeData.stats.called || 0}</b></div>
      <div><small>SERVING</small><b>${activeData.stats.serving}</b></div>
      <div><small>SCHEDULED</small><b>${activeData.stats.scheduled || 0}</b></div>
      <div><small>COMPLETED TODAY</small><b>${activeData.stats.completed}</b></div>
    `;
  }

  const queueEl = $("#queueRows");
  if (queueEl) {
    queueEl.innerHTML = activeData.queue.length
      ? activeData.queue.map(ticketRow).join("")
      : '<p class="muted empty-inline">No active customers in the queue.</p>';
  }

  const recentEl = $("#recentRows");
  if (recentEl) {
    const recent = activeData.recent_tickets || [];
    recentEl.innerHTML = recent.length
      ? recent
          .map(
            (t) =>
              `<p class="service-row"><b>${esc(t.token)}</b> ${esc(t.customer_name)} <small>${esc(
                t.status
              )} · ${esc(t.service_name || "General")}</small></p>`
          )
          .join("")
      : '<p class="muted empty-inline">No unarchived finished tickets today.</p>';
  }

  const apptEl = $("#appointmentsRows");
  if (apptEl) {
    apptEl.innerHTML = (activeData.appointments || []).length
      ? activeData.appointments.map(appointmentRow).join("")
      : '<p class="muted empty-inline">No upcoming scheduled appointments.</p>';
  }

  const perfEl = $("#perfPanel");
  if (perfEl && activeData.performance) {
    const p = activeData.performance;
    perfEl.innerHTML = `
      <div class="perf-grid">
        <div><small>COMPLETED</small><b>${p.completed_today}</b></div>
        <div><small>NO-SHOW</small><b>${p.no_show_today}</b></div>
        <div><small>CANCELLED</small><b>${p.cancelled_today}</b></div>
        <div><small>AVG WAIT</small><b>${p.avg_wait_minutes}m</b></div>
        <div><small>AVG SERVICE</small><b>${p.avg_service_minutes}m</b></div>
      </div>
      ${
        p.by_service?.length
          ? `<div class="perf-services">${p.by_service
              .map(
                (s) =>
                  `<p class="service-row">${esc(s.service_name)} <small>${s.total} total · ${s.completed} completed · ${s.waiting} waiting</small></p>`
              )
              .join("")}</div>`
          : ""
      }
    `;
  }
}

function setActiveTab(tabName) {
  activeTab = tabName;
  document.querySelectorAll("[data-tab]").forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.tab === tabName);
  });
  document.querySelectorAll("[data-panel]").forEach((panel) => {
    panel.classList.toggle("hidden", panel.dataset.panel !== tabName);
  });
}

async function manage(id, locationId = activeLocationId, tab = activeTab) {
  if (active && active !== id) {
    socket.emit("leave-business", active);
  }
  active = id;
  activeLocationId = locationId || "";
  activeTab = tab || "queue";

  const qs = activeLocationId ? `?location_id=${encodeURIComponent(activeLocationId)}` : "";
  const d = await api(`/api/businesses/${id}${qs}`);
  activeData = d;
  const b = d.business;
  const access = d.access || {};
  const canManage = Boolean(access.canManageBusiness);
  const canDelete = Boolean(access.canDeleteBusiness);
  const activeStaff = d.staff.filter((s) => s.is_active);

  $("#manageContent").innerHTML = `
    <div class="modal-header-bar">
      <div>
        <p class="eyebrow">LIVE OPERATIONS · ${esc(b.public_code)} · ${esc(b.status.toUpperCase())} · ${esc(b.timezone || "UTC")}</p>
        <h2>${esc(b.name)}</h2>
      </div>
      <div class="modal-header-right">
        ${
          d.locations.length
            ? `<select id="locationFilter" aria-label="Filter by branch">
                <option value="">All locations</option>
                ${d.locations
                  .map(
                    (l) =>
                      `<option value="${l.id}" ${
                        activeLocationId === l.id ? "selected" : ""
                      }>${esc(l.name)}</option>`
                  )
                  .join("")}
              </select>`
            : ""
        }
        <button class="close" id="manageClose" type="button" aria-label="Close">×</button>
      </div>
    </div>

    <p id="manageError" class="error"></p>

    <div class="queue-stats five-col" id="modalStats"></div>

    <div class="ops-bar">
      <div class="ops-group">
        <select id="nextStaffSelect" aria-label="Counter or staff">
          <option value="">Any counter / staff</option>
          ${activeStaff
            .map(
              (s) =>
                `<option value="${s.id}">${esc(
                  s.counter_label ? `${s.name} (${s.counter_label})` : s.name
                )}</option>`
            )
            .join("")}
        </select>
        <button class="btn" id="nextBtn" type="button">Call next customer →</button>
      </div>
      <div class="ops-group">
        <button class="btn ghost" id="addWalkin" type="button">＋ Walk-in token</button>
        <button class="btn ghost" id="manageShareBtn" type="button">QR &amp; short link</button>
        <a class="btn ghost" target="_blank" href="/q/${encodeURIComponent(b.public_code)}">Public screen ↗</a>
      </div>
    </div>

    <div class="workspace-tabs" role="tablist">
      <button class="tab-btn" data-tab="queue" type="button">Live Queue</button>
      <button class="tab-btn" data-tab="appointments" type="button">Appointments (${(d.appointments || []).length})</button>
      <button class="tab-btn" data-tab="performance" type="button">Performance</button>
      ${
        canManage
          ? `<button class="tab-btn" data-tab="setup" type="button">Locations, Services &amp; Team</button>
             <button class="tab-btn" data-tab="settings" type="button">Settings</button>`
          : ""
      }
    </div>

    <div id="inlineForm"></div>

    <section class="tab-panel" data-panel="queue">
      <div class="panel-head">
        <h3>Live queue</h3>
      </div>
      <div id="queueRows"></div>

      <div class="panel-head">
        <h3>Recent finished today</h3>
        <div class="row-btns">
          <button class="btn ghost small-btn" id="clearCompletedBtn" type="button">Clear completed today</button>
          <button class="btn ghost small-btn" id="closeStaleBtn" type="button">Close stale tickets</button>
        </div>
      </div>
      <div id="recentRows"></div>
    </section>

    <section class="tab-panel hidden" data-panel="appointments">
      <div class="panel-head">
        <h3>Scheduled appointments</h3>
      </div>
      <div id="appointmentsRows"></div>
    </section>

    <section class="tab-panel hidden" data-panel="performance">
      <div class="panel-head">
        <h3>Service performance overview</h3>
      </div>
      <div id="perfPanel"></div>
    </section>

    ${
      canManage
        ? `<section class="tab-panel hidden" data-panel="setup">
            <div class="panel-head">
              <h3>Locations / Branches</h3>
              <button class="btn ghost small-btn" id="addLocation" type="button">＋ Add location</button>
            </div>
            <div id="locationRows">
              ${
                d.locations.length
                  ? d.locations
                      .map(
                        (l) => `<div class="service-row row-flex">
                          <span>${esc(l.name)} <small>${esc(l.address || "No address")} · ${
                          l.is_active ? "active" : "inactive"
                        }</small></span>
                          <span class="row-btns">
                            <button class="btn ghost small-btn" data-edit-location="${l.id}" type="button">Edit</button>
                            <button class="btn ghost small-btn" data-toggle-location="${l.id}" data-active="${
                          l.is_active ? 0 : 1
                        }" type="button">${l.is_active ? "Disable" : "Enable"}</button>
                            <button class="btn ghost small-btn" data-delete-location="${l.id}" type="button">Delete</button>
                          </span>
                        </div>`
                      )
                      .join("")
                  : '<p class="muted empty-inline">Single main location.</p>'
              }
            </div>

            <div class="panel-head">
              <h3>Services</h3>
              <button class="btn ghost small-btn" id="addService" type="button">＋ Add service</button>
            </div>
            <div id="serviceRows">
              ${
                d.services.length
                  ? d.services
                      .map(
                        (s) => `<div class="service-row row-flex">
                          <span>${esc(s.name)} <small>${s.duration_minutes} min · ${Number(s.price).toFixed(2)} · ${
                          s.is_active ? "active" : "inactive"
                        }</small></span>
                          <span class="row-btns">
                            <button class="btn ghost small-btn" data-edit-service="${s.id}" type="button">Edit</button>
                            <button class="btn ghost small-btn" data-toggle-service="${s.id}" data-active="${
                          s.is_active ? 0 : 1
                        }" type="button">${s.is_active ? "Pause" : "Activate"}</button>
                            <button class="btn ghost small-btn" data-delete-service="${s.id}" type="button">Delete</button>
                          </span>
                        </div>`
                      )
                      .join("")
                  : '<p class="muted empty-inline">No services configured yet.</p>'
              }
            </div>

            <div class="panel-head">
              <h3>Team</h3>
              <button class="btn ghost small-btn" id="addStaff" type="button">＋ Add team member</button>
            </div>
            <div id="staffRows">
              ${
                d.staff.length
                  ? d.staff
                      .map(
                        (s) => `<div class="service-row row-flex">
                          <span>${esc(s.name)} <small>${esc(s.role)}${
                          s.counter_label ? ` · ${esc(s.counter_label)}` : ""
                        }${s.email ? ` · ${esc(s.email)}` : ""} · ${
                          s.is_active ? "active" : "inactive"
                        }</small></span>
                          <span class="row-btns">
                            <button class="btn ghost small-btn" data-edit-staff="${s.id}" type="button">Edit</button>
                            <button class="btn ghost small-btn" data-toggle-staff="${s.id}" data-active="${
                          s.is_active ? 0 : 1
                        }" type="button">${s.is_active ? "Deactivate" : "Activate"}</button>
                            <button class="btn ghost small-btn" data-delete-staff="${s.id}" type="button">Remove</button>
                          </span>
                        </div>`
                      )
                      .join("")
                  : '<p class="muted empty-inline">No team members added yet.</p>'
              }
            </div>
          </section>

          <section class="tab-panel hidden" data-panel="settings">
            <div class="panel-head">
              <h3>Business details</h3>
              <button class="btn ghost small-btn" id="editBusiness" type="button">Edit business</button>
            </div>
            <div class="settings-summary">
              <p class="service-row"><b>Name</b> <small>${esc(b.name)}</small></p>
              <p class="service-row"><b>Public code</b> <small>${esc(b.public_code)}</small></p>
              <p class="service-row"><b>Status</b> <small>${esc(b.status)}</small></p>
              <p class="service-row"><b>Timezone</b> <small>${esc(b.timezone || "UTC")}</small></p>
              <p class="service-row"><b>Address</b> <small>${esc(b.address || "Not set")}</small></p>
              <p class="service-row"><b>Phone</b> <small>${esc(b.phone || "Not set")}</small></p>
            </div>
            ${
              canDelete
                ? `<div class="danger-zone">
                    <div>
                      <strong>Danger zone</strong>
                      <p class="muted">Permanently delete this business workspace, services, and queue history.</p>
                    </div>
                    <button class="btn danger" id="deleteBusiness" type="button">Delete business</button>
                  </div>`
                : ""
            }
          </section>`
        : ""
    }
  `;

  renderTabPanels();
  setActiveTab(activeTab);

  if (!$("#manageDialog").open) {
    $("#manageDialog").showModal();
  }

  document.querySelectorAll("[data-tab]").forEach((btn) => {
    btn.onclick = () => {
      $("#inlineForm").innerHTML = "";
      setActiveTab(btn.dataset.tab);
    };
  });

  $("#manageClose").onclick = () => {
    socket.emit("leave-business", active);
    active = null;
    activeLocationId = "";
    activeData = null;
    $("#manageDialog").close();
  };

  if ($("#locationFilter")) {
    $("#locationFilter").onchange = (e) => {
      manage(id, e.target.value, activeTab).catch((err) => showManageError(err.message));
    };
  }

  if ($("#manageShareBtn")) {
    $("#manageShareBtn").onclick = () => openShareDialog(id, activeLocationId);
  }

  $("#nextBtn").onclick = async () => {
    showManageError("");
    try {
      const staff_id = $("#nextStaffSelect").value || undefined;
      await api(`/api/businesses/${id}/queue/next`, {
        method: "POST",
        body: JSON.stringify({
          staff_id,
          location_id: activeLocationId || undefined
        })
      });
      await manage(id, activeLocationId, activeTab);
      await load();
    } catch (e) {
      showManageError(e.message);
    }
  };

  $("#clearCompletedBtn").onclick = async () => {
    showManageError("");
    try {
      await api(`/api/businesses/${id}/queue/clear-completed`, { method: "POST" });
      await manage(id, activeLocationId, activeTab);
      await load();
    } catch (e) {
      showManageError(e.message);
    }
  };

  $("#closeStaleBtn").onclick = async () => {
    showManageError("");
    try {
      await api(`/api/businesses/${id}/queue/close-stale`, { method: "POST" });
      await manage(id, activeLocationId, activeTab);
      await load();
    } catch (e) {
      showManageError(e.message);
    }
  };

  $("#addWalkin").onclick = () =>
    inlineForm(
      `<h3>Issue walk-in token</h3>
      <form id="inline" class="inline-grid">
        <label>Customer name<input name="customer_name" placeholder="Full name" required></label>
        <label>Phone<input name="customer_phone" placeholder="Optional"></label>
        <label>Location
          <select name="location_id">
            <option value="">Main location</option>
            ${d.locations
              .filter((l) => l.is_active)
              .map(
                (l) =>
                  `<option value="${l.id}" ${
                    activeLocationId === l.id ? "selected" : ""
                  }>${esc(l.name)}</option>`
              )
              .join("")}
          </select>
        </label>
        <label>Service
          <select name="service_id">
            <option value="">General service</option>
            ${d.services
              .filter((s) => s.is_active)
              .map((s) => `<option value="${s.id}">${esc(s.name)}</option>`)
              .join("")}
          </select>
        </label>
        <label>Assign staff / counter
          <select name="staff_id">
            <option value="">Unassigned</option>
            ${activeStaff
              .map((s) => `<option value="${s.id}">${esc(s.name)}</option>`)
              .join("")}
          </select>
        </label>
        <div class="inline-submit">
          <button class="btn" type="submit">Issue token</button>
          <button class="btn ghost" type="button" data-close-inline="1">Cancel</button>
        </div>
      </form>`,
      `/api/businesses/${id}/tickets`
    );

  if (canManage) {
    $("#addLocation").onclick = () =>
      inlineForm(
        `<h3>New location / branch</h3>
        <form id="inline" class="inline-grid">
          <label>Branch name<input name="name" placeholder="e.g. Anna Nagar Branch" required></label>
          <label>Address<input name="address" placeholder="Street address"></label>
          <label>Phone<input name="phone" placeholder="Contact phone"></label>
          <div class="inline-submit">
            <button class="btn" type="submit">Save location</button>
            <button class="btn ghost" type="button" data-close-inline="1">Cancel</button>
          </div>
        </form>`,
        `/api/businesses/${id}/locations`
      );

    $("#addService").onclick = () =>
      inlineForm(
        `<h3>New service</h3>
        <form id="inline" class="inline-grid">
          <label>Service name<input name="name" placeholder="e.g. General Consultation" required></label>
          <label>Duration (minutes)<input name="duration_minutes" type="number" value="15" min="5"></label>
          <label>Price<input name="price" type="number" min="0" step=".01" placeholder="0.00"></label>
          <div class="inline-submit">
            <button class="btn" type="submit">Save service</button>
            <button class="btn ghost" type="button" data-close-inline="1">Cancel</button>
          </div>
        </form>`,
        `/api/businesses/${id}/services`
      );

    $("#addStaff").onclick = () =>
      inlineForm(
        `<h3>Add team member</h3>
        <form id="inline" class="inline-grid">
          <label>Full name<input name="name" placeholder="e.g. Dr. Karthik" required></label>
          <label>Login email (optional)<input name="email" type="email" placeholder="staff@clinic.com"></label>
          <label>Counter / desk label<input name="counter_label" placeholder="e.g. Counter 01"></label>
          <label>Role
            <select name="role">
              <option value="staff">staff</option>
              <option value="manager">manager</option>
              <option value="counter">counter</option>
            </select>
          </label>
          <div class="inline-submit">
            <button class="btn" type="submit">Add member</button>
            <button class="btn ghost" type="button" data-close-inline="1">Cancel</button>
          </div>
        </form>`,
        `/api/businesses/${id}/staff`
      );

    $("#editBusiness").onclick = () =>
      inlineForm(
        `<h3>Edit business details</h3>
        <form id="inline" class="inline-grid">
          <label>Business name<input name="name" value="${esc(b.name)}" required></label>
          <label>Address<input name="address" value="${esc(b.address || "")}" placeholder="Address"></label>
          <label>Phone<input name="phone" value="${esc(b.phone || "")}" placeholder="Phone"></label>
          <label>Timezone (IANA)<input name="timezone" value="${esc(b.timezone || "UTC")}" placeholder="e.g. Asia/Kolkata"></label>
          ${
            b.status !== "suspended"
              ? `<label>Status
                  <select name="status">
                    <option value="active" ${b.status === "active" ? "selected" : ""}>active</option>
                    <option value="paused" ${b.status === "paused" ? "selected" : ""}>paused</option>
                  </select>
                </label>`
              : '<span class="error">Suspended by platform admin</span>'
          }
          <div class="inline-submit">
            <button class="btn" type="submit">Save changes</button>
            <button class="btn ghost" type="button" data-close-inline="1">Cancel</button>
          </div>
        </form>`,
        `/api/businesses/${id}`,
        "PATCH"
      );

    if (canDelete) {
      $("#deleteBusiness").onclick = async (e) => {
        const btn = e.currentTarget;
        if (!btn.dataset.armed) {
          btn.dataset.armed = "1";
          btn.textContent = "Confirm delete business?";
          return;
        }
        try {
          await api(`/api/businesses/${id}`, { method: "DELETE" });
          socket.emit("leave-business", id);
          active = null;
          activeLocationId = "";
          activeData = null;
          $("#manageDialog").close();
          await load();
        } catch (err) {
          showManageError(err.message);
        }
      };
    }
  }

  socket.emit("join-business", id);
}

function inlineForm(html, url, method = "POST") {
  const container = $("#inlineForm");
  container.innerHTML = html;
  container.scrollIntoView({ behavior: "smooth", block: "nearest" });
  const closeBtn = container.querySelector("[data-close-inline]");
  if (closeBtn) {
    closeBtn.onclick = () => {
      container.innerHTML = "";
    };
  }
  $("#inline").onsubmit = async (e) => {
    e.preventDefault();
    showManageError("");
    const o = Object.fromEntries(new FormData(e.target));
    try {
      await api(url, { method, body: JSON.stringify(o) });
      await manage(active, activeLocationId, activeTab);
      await load();
    } catch (err) {
      showManageError(err.message);
    }
  };
}

document.addEventListener("change", async (e) => {
  if (!active) return;
  if (e.target.matches("[data-status]")) {
    showManageError("");
    try {
      await api(`/api/tickets/${e.target.dataset.status}/status`, {
        method: "POST",
        body: JSON.stringify({ status: e.target.value })
      });
      await manage(active, activeLocationId, activeTab);
      await load();
    } catch (err) {
      showManageError(err.message);
    }
  } else if (e.target.matches("[data-assign]")) {
    showManageError("");
    try {
      const tid = e.target.dataset.assign;
      const ticket = activeData?.queue?.find((q) => q.id === tid);
      await api(`/api/tickets/${tid}/status`, {
        method: "POST",
        body: JSON.stringify({
          status: ticket?.status || "waiting",
          staff_id: e.target.value || null
        })
      });
      await manage(active, activeLocationId, activeTab);
    } catch (err) {
      showManageError(err.message);
    }
  }
});

document.addEventListener("click", async (e) => {
  if (!active) return;
  const btn = e.target.closest("button");
  if (!btn) return;
  try {
    if (btn.dataset.checkin) {
      await api(`/api/tickets/${btn.dataset.checkin}/check-in`, { method: "POST" });
      await manage(active, activeLocationId, activeTab);
      await load();
    } else if (btn.dataset.cancelAppt) {
      await api(`/api/tickets/${btn.dataset.cancelAppt}/status`, {
        method: "POST",
        body: JSON.stringify({ status: "cancelled" })
      });
      await manage(active, activeLocationId, activeTab);
      await load();
    } else if (btn.dataset.editLocation) {
      const loc = activeData?.locations?.find((l) => l.id === btn.dataset.editLocation);
      if (loc) {
        inlineForm(
          `<h3>Edit location</h3>
          <form id="inline" class="inline-grid">
            <label>Branch name<input name="name" value="${esc(loc.name)}" required></label>
            <label>Address<input name="address" value="${esc(loc.address || "")}" placeholder="Address"></label>
            <label>Phone<input name="phone" value="${esc(loc.phone || "")}" placeholder="Phone"></label>
            <div class="inline-submit">
              <button class="btn" type="submit">Update location</button>
              <button class="btn ghost" type="button" data-close-inline="1">Cancel</button>
            </div>
          </form>`,
          `/api/locations/${loc.id}`,
          "PATCH"
        );
      }
    } else if (btn.dataset.editService) {
      const svc = activeData?.services?.find((s) => s.id === btn.dataset.editService);
      if (svc) {
        inlineForm(
          `<h3>Edit service</h3>
          <form id="inline" class="inline-grid">
            <label>Service name<input name="name" value="${esc(svc.name)}" required></label>
            <label>Duration (minutes)<input name="duration_minutes" type="number" min="5" value="${svc.duration_minutes}"></label>
            <label>Price<input name="price" type="number" min="0" step=".01" value="${svc.price}"></label>
            <div class="inline-submit">
              <button class="btn" type="submit">Update service</button>
              <button class="btn ghost" type="button" data-close-inline="1">Cancel</button>
            </div>
          </form>`,
          `/api/services/${svc.id}`,
          "PATCH"
        );
      }
    } else if (btn.dataset.editStaff) {
      const member = activeData?.staff?.find((s) => s.id === btn.dataset.editStaff);
      if (member) {
        inlineForm(
          `<h3>Edit team member</h3>
          <form id="inline" class="inline-grid">
            <label>Full name<input name="name" value="${esc(member.name)}" required></label>
            <label>Email<input name="email" type="email" value="${esc(member.email || "")}" placeholder="Email"></label>
            <label>Counter label<input name="counter_label" value="${esc(member.counter_label || "")}" placeholder="Counter label"></label>
            <label>Role
              <select name="role">
                <option value="staff" ${member.role === "staff" ? "selected" : ""}>staff</option>
                <option value="manager" ${member.role === "manager" ? "selected" : ""}>manager</option>
                <option value="counter" ${member.role === "counter" ? "selected" : ""}>counter</option>
              </select>
            </label>
            <div class="inline-submit">
              <button class="btn" type="submit">Update member</button>
              <button class="btn ghost" type="button" data-close-inline="1">Cancel</button>
            </div>
          </form>`,
          `/api/staff/${member.id}`,
          "PATCH"
        );
      }
    } else if (btn.dataset.toggleService) {
      await api(`/api/services/${btn.dataset.toggleService}`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: btn.dataset.active === "1" })
      });
      await manage(active, activeLocationId, activeTab);
    } else if (btn.dataset.deleteService) {
      await api(`/api/services/${btn.dataset.deleteService}`, { method: "DELETE" });
      await manage(active, activeLocationId, activeTab);
      await load();
    } else if (btn.dataset.toggleLocation) {
      await api(`/api/locations/${btn.dataset.toggleLocation}`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: btn.dataset.active === "1" })
      });
      await manage(active, activeLocationId, activeTab);
    } else if (btn.dataset.deleteLocation) {
      await api(`/api/locations/${btn.dataset.deleteLocation}`, { method: "DELETE" });
      if (activeLocationId === btn.dataset.deleteLocation) activeLocationId = "";
      await manage(active, activeLocationId, activeTab);
    } else if (btn.dataset.toggleStaff) {
      await api(`/api/staff/${btn.dataset.toggleStaff}`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: btn.dataset.active === "1" })
      });
      await manage(active, activeLocationId, activeTab);
    } else if (btn.dataset.deleteStaff) {
      await api(`/api/staff/${btn.dataset.deleteStaff}`, { method: "DELETE" });
      await manage(active, activeLocationId, activeTab);
    }
  } catch (err) {
    showManageError(err.message);
  }
});

$("#newBusiness").onclick = () => {
  $("#businessError").textContent = "";
  $("#businessDialog").showModal();
};
$("#businessClose").onclick = () => $("#businessDialog").close();
$("#businessForm").onsubmit = async (e) => {
  e.preventDefault();
  $("#businessError").textContent = "";
  const o = Object.fromEntries(new FormData(e.target));
  try {
    await api("/api/businesses", { method: "POST", body: JSON.stringify(o) });
    $("#businessDialog").close();
    e.target.reset();
    await load();
  } catch (err) {
    $("#businessError").textContent = err.message;
  }
};

async function handleLogout() {
  try {
    await api("/api/auth/logout", { method: "POST" });
  } finally {
    location.href = "/";
  }
}

$("#logout").onclick = handleLogout;
if ($("#topLogout")) $("#topLogout").onclick = handleLogout;

$("#changePasswordForm").onsubmit = async (e) => {
  e.preventDefault();
  $("#pwMsg").textContent = "";
  const o = Object.fromEntries(new FormData(e.target));
  try {
    await api("/api/auth/change-password", { method: "POST", body: JSON.stringify(o) });
    e.target.reset();
    $("#pwMsg").textContent = "Password updated.";
  } catch (err) {
    $("#pwMsg").textContent = err.message;
  }
};

$("#forcePasswordForm").onsubmit = async (e) => {
  e.preventDefault();
  $("#forcePwError").textContent = "";
  const o = Object.fromEntries(new FormData(e.target));
  try {
    await api("/api/auth/change-password", { method: "POST", body: JSON.stringify(o) });
    $("#forcePasswordDialog").close();
    e.target.reset();
    await load();
  } catch (err) {
    $("#forcePwError").textContent = err.message;
  }
};

init().catch((err) => {
  const list = $("#businessList");
  if (list) {
    list.innerHTML = `<div class="empty error">${esc(err?.message || "Failed to load workspace.")}</div>`;
  }
});
