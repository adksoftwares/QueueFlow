const $ = (s) => document.querySelector(s);
const code = new URLSearchParams(location.search).get("code") || "";

let selectedLocationId = new URLSearchParams(location.search).get("location_id") || "";
let activeLookupToken = "";
let activeLookupKey = "";
let soundAlertsEnabled = true;
let audioCtx = null;
let prevTicketSnapshot = null;
let lastAlertKey = "";
let bannerDismissedKey = "";
const baseDocTitle = document.title;

function getTokenStorageKey() {
  return `queueflow_token_${String(code || "").toUpperCase()}`;
}

function saveTrackedToken(token, lookupKey = "") {
  activeLookupToken = token || "";
  activeLookupKey = lookupKey || "";
  try {
    if (activeLookupToken) {
      localStorage.setItem(getTokenStorageKey(), JSON.stringify({ token: activeLookupToken, key: activeLookupKey }));
    } else {
      localStorage.removeItem(getTokenStorageKey());
    }
  } catch {
    // ignore storage errors
  }
}

function loadTrackedToken() {
  try {
    const stored = localStorage.getItem(getTokenStorageKey()) || "";
    if (!stored) return "";
    try {
      const parsed = JSON.parse(stored);
      activeLookupKey = parsed.key || "";
      return parsed.token || "";
    } catch {
      activeLookupKey = "";
      return stored;
    }
  } catch {
    return "";
  }
}

function unlockAudio() {
  const AudioContextCtor = window.AudioContext || window.webkitAudioContext;
  if (!AudioContextCtor) return null;
  if (!audioCtx) {
    try {
      audioCtx = new AudioContextCtor();
    } catch {
      return null;
    }
  }
  if (audioCtx.state === "suspended") {
    audioCtx.resume().catch(() => {});
  }
  return audioCtx;
}

function playAlertChime(urgent = false) {
  if (!soundAlertsEnabled) return;
  const ctx = unlockAudio();
  if (!ctx) return;

  const notes = urgent ? [659.25, 880, 1046.5] : [587.33, 880];
  const now = ctx.currentTime;
  notes.forEach((freq, i) => {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(freq, now + i * 0.14);
    gain.gain.setValueAtTime(0.001, now + i * 0.14);
    gain.gain.exponentialRampToValueAtTime(0.18, now + i * 0.14 + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.001, now + i * 0.14 + 0.28);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start(now + i * 0.14);
    osc.stop(now + i * 0.14 + 0.3);
  });
}

function maybeRequestNotifications() {
  if ("Notification" in window && Notification.permission === "default") {
    Notification.requestPermission().catch(() => {});
  }
}

function sendBrowserNotification(title, body, tag) {
  if (!soundAlertsEnabled) return;
  if ("Notification" in window && Notification.permission === "granted") {
    try {
      new Notification(title, { body, tag });
    } catch {
      // ignore on platforms disallowing constructor
    }
  }
  if (navigator.vibrate) {
    navigator.vibrate([180, 80, 180]);
  }
}

function renderAlertBanner({ title, body, variant = "next", key = "" }) {
  const banner = $("#nextAlertBanner");
  if (!banner) return;
  if (!title || (key && bannerDismissedKey === key)) {
    banner.classList.add("hidden");
    banner.innerHTML = "";
    document.title = baseDocTitle;
    return;
  }

  banner.classList.remove("hidden", "is-turn", "is-soon");
  if (variant === "turn") banner.classList.add("is-turn");
  else if (variant === "soon") banner.classList.add("is-soon");
  banner.innerHTML = `
    <div class="next-alert-body">
      <strong>${esc(title)}</strong>
      <span>${esc(body)}</span>
    </div>
    <button type="button" class="next-alert-close" id="dismissAlertBanner" aria-label="Dismiss alert">×</button>
  `;
  $("#dismissAlertBanner").onclick = () => {
    bannerDismissedKey = key;
    banner.classList.add("hidden");
    document.title = baseDocTitle;
  };
  const prefix =
    variant === "turn" ? "(YOUR TURN!)" : variant === "soon" ? "(~30 MIN!)" : "(YOU'RE NEXT!)";
  document.title = `${prefix} ${baseDocTitle}`;
}

function evaluateQueueAlerts(t) {
  if (!t) {
    renderAlertBanner({ title: "" });
    return;
  }

  const prev = prevTicketSnapshot && prevTicketSnapshot.token === t.token ? prevTicketSnapshot : null;
  const activeToken = t.current_active?.token || "";
  const activeStatus = t.current_active?.status || "";
  const activeCounter = t.current_active?.counter_label || t.current_active?.staff_name || "";
  const myCounter = t.counter_label || t.staff_name || "";

  let alertInfo = null;

  if (t.status === "called" || t.status === "serving") {
    const key = `turn:${t.token}:${t.status}:${myCounter}`;
    alertInfo = {
      key,
      variant: "turn",
      urgent: true,
      title: `Your turn now — Token ${t.token} is ${t.status}`,
      body: myCounter
        ? `Please proceed to ${myCounter}.`
        : "Please proceed to the counter now."
    };
  } else if (t.status === "waiting" && t.position_ahead === 0 && t.current_active) {
    const key = `next_active:${t.token}:${activeToken}:${activeStatus}`;
    const where = activeCounter ? ` (${activeCounter})` : "";
    const waitNote = t.estimated_wait_minutes ? ` (~${t.estimated_wait_minutes} min est.)` : "";
    alertInfo = {
      key,
      variant: "next",
      urgent: false,
      title: `Get ready — You are NEXT (${t.token})`,
      body: `Token ${activeToken} is now ${activeStatus}${where}${waitNote}. Please stay ready.`
    };
  } else if (t.status === "waiting" && t.alert_30m) {
    const key = `soon_30m:${t.token}`;
    const aheadCount = Number(t.tickets_ahead || 0);
    const estMin = Number(t.estimated_wait_minutes || 0);
    alertInfo = {
      key,
      variant: "soon",
      urgent: false,
      title: `~${estMin} min away — Your turn is approaching (${t.token})`,
      body: `${aheadCount} customer${aheadCount === 1 ? "" : "s"} ahead (~${estMin} min est.). Please get ready to arrive.`
    };
  } else if (
    t.status === "waiting" &&
    t.position_ahead === 0 &&
    prev &&
    prev.position_ahead !== null &&
    prev.position_ahead > 0
  ) {
    const key = `next_first:${t.token}`;
    alertInfo = {
      key,
      variant: "next",
      urgent: false,
      title: `You are next in line (${t.token})`,
      body: "No one is waiting ahead of you — please be ready."
    };
  }

  prevTicketSnapshot = {
    token: t.token,
    status: t.status,
    position_ahead: t.position_ahead,
    activeToken,
    activeStatus
  };

  if (!alertInfo) {
    renderAlertBanner({ title: "" });
    return;
  }

  renderAlertBanner(alertInfo);

  if (alertInfo.key !== lastAlertKey) {
    lastAlertKey = alertInfo.key;
    playAlertChime(alertInfo.urgent);
    sendBrowserNotification(alertInfo.title, alertInfo.body, alertInfo.key);
  }
}

async function api(url, opt = {}) {
  const r = await fetch(url, {
    ...opt,
    headers: { "Content-Type": "application/json", ...(opt.headers || {}) }
  });
  const d = await r.json().catch(() => ({}));
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

function paint(q, stats) {
  $("#waitingCount").textContent = stats.waiting ?? 0;
  $("#calledCount").textContent = stats.called ?? 0;
  $("#servingCount").textContent = stats.serving ?? 0;
  $("#completedCount").textContent = stats.completed ?? 0;

  $("#publicQueue").innerHTML = q.length
    ? q
        .map((t) => {
          const counter = [t.location_name, t.counter_label || t.staff_name]
            .filter(Boolean)
            .join(" · ");
          const subtitle = [t.service_name || "General service", counter]
            .filter(Boolean)
            .join(" · ");
          return `<div class="ticket-public ${t.status === "serving" ? "is-serving" : ""}">
            <b>${esc(t.token)}</b>
            <span>${esc(subtitle)}</span>
            <small class="status-tag status-${esc(t.status)}">${esc(t.status)}</small>
          </div>`;
        })
        .join("")
    : '<p class="muted">The queue is currently clear.</p>';
}

async function refreshPublicQueue() {
  const qs = selectedLocationId ? `?location_id=${encodeURIComponent(selectedLocationId)}` : "";
  const d = await api(`/api/public/${encodeURIComponent(code)}${qs}`);
  paint(d.queue, d.stats);
  return d;
}

async function refreshLookup() {
  if (!activeLookupToken) {
    renderAlertBanner({ title: "" });
    return;
  }
  try {
    const d = await api(
      `/api/public/${encodeURIComponent(code)}/tickets/${encodeURIComponent(activeLookupToken)}?key=${encodeURIComponent(activeLookupKey)}`
    );
    const t = d.ticket;
    evaluateQueueAlerts(t);

    const rows = [
      ["Status", t.status],
      ["Service", t.service_name || "General service"],
      t.location_name ? ["Branch", t.location_name] : null,
      t.counter_label || t.staff_name ? ["Assigned", t.counter_label || t.staff_name] : null,
      t.position_ahead !== null
        ? [
            "Queue position",
            t.position_ahead === 0 ? "Next in line" : `${t.position_ahead} ahead of you`
          ]
        : null,
      t.estimated_wait_minutes !== null && t.estimated_wait_minutes !== undefined
        ? ["Est. wait", t.estimated_wait_minutes > 0 ? `~${t.estimated_wait_minutes} min` : "Up next"]
        : null
    ].filter(Boolean);

    $("#lookupResult").innerHTML = `<div class="my-token lookup-details">
      <div class="lookup-head-row">
        <small>TOKEN ${esc(t.token)} · ${esc(t.queue_date)}</small>
        <button type="button" class="btn ghost small-btn" id="clearTrackedToken">Clear</button>
      </div>
      <div class="lookup-grid">
        ${rows
          .map(
            ([label, val]) =>
              `<div class="lookup-item"><span>${esc(label)}</span><b>${esc(val)}</b></div>`
          )
          .join("")}
      </div>
    </div>`;

    if ($("#clearTrackedToken")) {
      $("#clearTrackedToken").onclick = () => {
        saveTrackedToken("", "");
        prevTicketSnapshot = null;
        lastAlertKey = "";
        bannerDismissedKey = "";
        $("#lookupResult").innerHTML = "";
        renderAlertBanner({ title: "" });
      };
    }
  } catch (err) {
    $("#lookupResult").innerHTML = `<p class="error">${esc(err.message)}</p>`;
  }
}

async function syncAll() {
  await refreshPublicQueue().catch(() => {});
  if (activeLookupToken) {
    await refreshLookup().catch(() => {});
  }
}

async function init() {
  if (!code) throw Error("Business code is missing");
  activeLookupToken = loadTrackedToken();

  const soundBtn = $("#alertSoundBtn");
  if (soundBtn) {
    soundBtn.onclick = () => {
      soundAlertsEnabled = !soundAlertsEnabled;
      soundBtn.textContent = soundAlertsEnabled ? "🔔 Alerts: On" : "🔕 Alerts: Muted";
      if (soundAlertsEnabled) {
        unlockAudio();
        maybeRequestNotifications();
        playAlertChime(false);
      }
    };
  }

  const d = await refreshPublicQueue();
  $("#businessName").textContent = d.business.name;
  $("#businessMeta").textContent = [
    d.business.category,
    d.business.address,
    d.business.phone
  ]
    .filter(Boolean)
    .join(" · ");

  if (d.locations && d.locations.length) {
    $("#locationField").classList.remove("hidden");
    $("#locationSelect").innerHTML =
      '<option value="">All / Main location</option>' +
      d.locations
        .map(
          (l) =>
            `<option value="${l.id}" ${
              selectedLocationId === l.id ? "selected" : ""
            }>${esc(l.name)}</option>`
        )
        .join("");
    $("#locationSelect").onchange = (e) => {
      selectedLocationId = e.target.value;
      refreshPublicQueue().catch(() => {});
    };
  }

  $("#serviceSelect").innerHTML =
    '<option value="">General service</option>' +
    d.services
      .map(
        (s) =>
          `<option value="${s.id}">${esc(s.name)} · ${s.duration_minutes} min</option>`
      )
      .join("");

  if (activeLookupToken) {
    const tokenInput = $("#lookupForm input[name='token']");
    if (tokenInput) tokenInput.value = activeLookupToken;
    const keyInput = $("#lookupForm input[name='lookup_key']");
    if (keyInput) keyInput.value = activeLookupKey;
    await refreshLookup();
  }

  const socket = io({ transports: ["websocket", "polling"] });
  socket.on("connect", () => socket.emit("join-public", code));
  socket.on("queue:update", (x) => {
    if (selectedLocationId) {
      refreshPublicQueue().catch(() => {});
    } else {
      paint(x.tickets, x.stats);
    }
    if (activeLookupToken) {
      refreshLookup().catch(() => {});
    }
  });

  setInterval(() => {
    if (!document.hidden) syncAll();
  }, 5000);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) syncAll();
  });
}

$("#joinForm").onsubmit = async (e) => {
  e.preventDefault();
  $("#joinError").textContent = "";
  unlockAudio();
  maybeRequestNotifications();
  try {
    const payload = Object.fromEntries(new FormData(e.target));
    const d = await api(`/api/public/${encodeURIComponent(code)}/tickets`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
    const isScheduled = d.ticket.status === "scheduled";
    const apptText =
      isScheduled && d.ticket.appointment_at
        ? `Scheduled for ${new Date(d.ticket.appointment_at).toLocaleString()}.`
        : "Keep this page open — we will alert you when you are next.";
    $("#ticketResult").innerHTML = `<div class="my-token">
      <small>${isScheduled ? "APPOINTMENT REQUEST CONFIRMED" : "YOUR TOKEN NUMBER"}</small>
      <b>${esc(d.ticket.token)}</b>
      <span>Private tracking key: <strong>${esc(d.ticket.lookup_key)}</strong></span>
      <span>${esc(apptText)}</span>
    </div>`;
    saveTrackedToken(d.ticket.token, d.ticket.lookup_key);
    prevTicketSnapshot = null;
    lastAlertKey = "";
    bannerDismissedKey = "";
    e.target.reset();
    if (selectedLocationId && $("#locationSelect")) {
      $("#locationSelect").value = selectedLocationId;
    }
    await syncAll();
  } catch (err) {
    $("#joinError").textContent = err.message;
  }
};

$("#lookupForm").onsubmit = async (e) => {
  e.preventDefault();
  unlockAudio();
  maybeRequestNotifications();
  const fd = new FormData(e.target);
  const token = String(fd.get("token") || "").trim().toUpperCase();
  const lookupKey = String(fd.get("lookup_key") || "").trim();
  if (!token || !lookupKey) return;
  saveTrackedToken(token, lookupKey);
  prevTicketSnapshot = null;
  lastAlertKey = "";
  bannerDismissedKey = "";
  await refreshLookup();
};

init().catch((e) => {
  $("#businessName").textContent = "Service unavailable";
  $("#businessMeta").textContent = e.message;
});
