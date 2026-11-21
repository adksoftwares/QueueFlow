const $ = (s) => document.querySelector(s);

let mode = "login";

function dialog(m, initialError = "", initialSuccess = "") {
  mode = m;
  const isRegister = m === "register";
  const isMfa = m === "mfa";
  const isReset = m === "reset";
  const isCreds = !isMfa && !isReset;

  $("#credentialsFields").classList.toggle("hidden", !isCreds);
  $("#mfaFields").classList.toggle("hidden", !isMfa);
  $("#resetFields").classList.toggle("hidden", !isReset);
  $("#nameField").classList.toggle("hidden", !isRegister);

  const nameInput = $("#nameInput");
  const emailInput = $("#emailInput");
  const passInput = $("#passwordInput");
  const mfaInput = $("#mfaCodeInput");
  const resetTokenInput = $("#resetTokenInput");
  const resetPassInput = $("#resetPassInput");

  nameInput.disabled = !isRegister;
  nameInput.required = isRegister;

  emailInput.disabled = !isCreds;
  emailInput.required = isCreds;
  passInput.disabled = !isCreds;
  passInput.required = isCreds;
  passInput.autocomplete = isRegister ? "new-password" : "current-password";

  mfaInput.disabled = !isMfa;
  mfaInput.required = isMfa;

  resetTokenInput.disabled = !isReset;
  resetTokenInput.required = isReset;
  resetPassInput.disabled = !isReset;
  resetPassInput.required = isReset;

  if (isRegister) {
    $("#authTitle").textContent = "Create your owner account";
    $("#authSubmit").textContent = "Create account";
    $("#authSwitch").innerHTML = 'Already registered? <a href="#">Sign in</a>';
    $("#authExtraLink").classList.add("hidden");
  } else if (isMfa) {
    $("#authTitle").textContent = "Two-factor verification";
    $("#authSubmit").textContent = "Verify & sign in";
    $("#authSwitch").innerHTML = '<a href="#">Back to sign in</a>';
    $("#authExtraLink").classList.add("hidden");
  } else if (isReset) {
    $("#authTitle").textContent = "Reset your password";
    $("#authSubmit").textContent = "Set new password";
    $("#authSwitch").innerHTML = '<a href="#">Back to sign in</a>';
    $("#authExtraLink").classList.add("hidden");
  } else {
    $("#authTitle").textContent = "Welcome back";
    $("#authSubmit").textContent = "Sign in";
    $("#authSwitch").innerHTML = 'New to QueueFlow? <a href="#">Create account</a>';
    $("#authExtraLink").classList.remove("hidden");
  }

  $("#authError").textContent = initialError;
  $("#authSuccess").textContent = initialSuccess;

  if (!$("#authDialog").open) {
    $("#authDialog").showModal();
  }

  if (isRegister) nameInput.focus();
  else if (isMfa) mfaInput.focus();
  else if (isReset) (resetTokenInput.value ? resetPassInput : resetTokenInput).focus();
  else emailInput.focus();
}

$("#loginOpen").onclick = () => dialog("login");
["#registerOpen", "#heroStart"].forEach((s) => {
  $(s).onclick = () => dialog("register");
});
$("#authClose").onclick = () => $("#authDialog").close();
$("#openResetLink").onclick = (e) => {
  e.preventDefault();
  dialog("reset");
};

$("#authSwitch").onclick = (e) => {
  if (e.target.tagName === "A") {
    e.preventDefault();
    if (mode === "login") dialog("register");
    else dialog("login");
  }
};

$("#authForm").onsubmit = async (e) => {
  e.preventDefault();
  $("#authError").textContent = "";
  $("#authSuccess").textContent = "";
  const data = Object.fromEntries(new FormData(e.target));

  try {
    if (mode === "reset") {
      const r = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
      const x = await r.json().catch(() => ({}));
      if (!r.ok) throw Error(x.error || "Reset failed");
      $("#resetTokenInput").value = "";
      $("#resetPassInput").value = "";
      dialog("login", "", "Password updated. You can now sign in.");
      return;
    }

    const endpoint =
      mode === "mfa"
        ? "/api/auth/mfa/verify"
        : `/api/auth/${mode}`;

    const r = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });
    const x = await r.json().catch(() => ({}));
    if (!r.ok) throw Error(x.error || "Authentication failed");

    if (x.mfaRequired) {
      $("#mfaCodeInput").value = "";
      dialog("mfa");
      return;
    }

    if (x.user?.role === "super_admin") {
      location.href = "/super-admin.html";
    } else {
      location.href = "/dashboard.html";
    }
  } catch (err) {
    $("#authError").textContent = err.message;
  }
};

const params = new URLSearchParams(location.search);
if (params.get("resetToken")) {
  $("#resetTokenInput").value = params.get("resetToken");
  dialog("reset");
} else if (params.get("expired") === "1") {
  dialog("login", "Your session expired. Please sign in again.");
}

async function syncAuthNav() {
  try {
    const r = await fetch("/api/auth/me");
    const d = await r.json().catch(() => ({}));
    const user = d?.user || null;
    if (!user) return;

    $("#loginOpen").classList.add("hidden");
    $("#registerOpen").classList.add("hidden");
    const wsLink = $("#workspaceLink");
    if (wsLink) {
      wsLink.href = user.role === "super_admin" ? "/super-admin.html" : "/dashboard.html";
      wsLink.textContent = user.role === "super_admin" ? "Super Admin" : "Open workspace";
      wsLink.classList.remove("hidden");
    }
    const logoutBtn = $("#homeLogout");
    if (logoutBtn) {
      logoutBtn.classList.remove("hidden");
      logoutBtn.onclick = async () => {
        await fetch("/api/auth/logout", { method: "POST" });
        location.reload();
      };
    }
  } catch {
    // ignore
  }
}

syncAuthNav();
