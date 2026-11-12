/* Admin page: the password dialog and the per-user access editor.
   Passwords are entered only inside the dialog's two inputs and submitted
   as a plain form POST — never in a URL, an attribute, or a JS variable.
   The rules below mirror the server's password policy; the server
   re-checks them and the two-entry match on every request.

   The server replaces the user's stored access set with the set the
   panel posts. */
(function () {
  "use strict";

  var overlay = document.getElementById("pw-dialog");
  if (!overlay) return;

  var form = document.getElementById("pw-dialog-form");
  var usernameField = document.getElementById("pw-username");
  var userField = document.getElementById("pw-user");
  var roleField = document.getElementById("pw-role");
  var title = document.getElementById("pw-dialog-title");
  var summary = document.getElementById("pw-summary");
  var pw1 = document.getElementById("pw-1");
  var pw2 = document.getElementById("pw-2");
  var checklist = document.getElementById("pw-checklist");
  var matchLine = document.getElementById("pw-match");
  var confirmBtn = document.getElementById("pw-confirm");
  var cancelBtn = document.getElementById("pw-cancel");
  var createForm = document.getElementById("create-form");
  var createBtn = document.getElementById("create-with-pw");

  var RULES = {
    length: function (v) { return v.length >= 12; },
    upper: function (v) { return /[A-Z]/.test(v); },
    lower: function (v) { return /[a-z]/.test(v); },
    digit: function (v) { return /[0-9]/.test(v); },
    symbol: function (v) { return /[^A-Za-z0-9]/.test(v); },
  };

  var trigger = null;

  function open(mode, target, username) {
    form.action = target;
    usernameField.value = username || "";
    userField.value = mode === "reset" ? username : "";
    roleField.value = "user";
    pw1.value = "";
    pw2.value = "";
    if (mode === "create") {
      var name = document.getElementById("new-username").value;
      var role = document.getElementById("new-role").value;
      title.textContent = "Create user";
      usernameField.value = name;
      roleField.value = role;
      confirmBtn.textContent = "Create user";
      summary.textContent = "Creating \u201c" + name + "\u201d as " + role + ".";
      summary.classList.remove("hidden");
    } else {
      title.textContent = "Reset password for " + username;
      confirmBtn.textContent = "Reset password";
      summary.classList.add("hidden");
    }
    overlay.classList.remove("hidden");
    update();
    pw1.focus();
  }

  function close() {
    // Wipe the entries so a password never lingers in the DOM.
    pw1.value = "";
    pw2.value = "";
    overlay.classList.add("hidden");
    if (trigger) trigger.focus();
  }

  function update() {
    var v = pw1.value;
    var allPass = true;
    Array.prototype.forEach.call(checklist.children, function (li) {
      var ok = RULES[li.getAttribute("data-rule")](v);
      li.classList.toggle("ok", ok);
      if (!ok) allPass = false;
    });

    var text = "";
    var bad = false;
    if (pw2.value !== "") {
      if (v !== pw2.value) {
        text = "Passwords do not match.";
        bad = true;
      } else if (!allPass) {
        text = "Entries match — fix the checklist items.";
      }
    }
    matchLine.textContent = text;
    matchLine.classList.toggle("bad", bad);
    confirmBtn.disabled = !(pw2.value !== "" && v === pw2.value && allPass);
  }

  createBtn.addEventListener("click", function () {
    trigger = createBtn;
    open("create", createForm.action, null);
  });
  createForm.addEventListener("submit", function (e) {
    e.preventDefault();
    trigger = createBtn;
    open("create", createForm.action, null);
  });

  var resetBtn = document.querySelector(".reset-btn");
  if (resetBtn) {
    resetBtn.addEventListener("click", function () {
      trigger = resetBtn;
      open("reset", resetBtn.getAttribute("data-action"),
           resetBtn.getAttribute("data-username"));
    });
  }

  cancelBtn.addEventListener("click", close);
  pw1.addEventListener("input", update);
  pw2.addEventListener("input", update);
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !overlay.classList.contains("hidden")) close();
  });
  overlay.addEventListener("click", function (e) {
    if (e.target === overlay) close();
  });

  var panel = document.querySelector(".user-panel");
  if (!panel) return;

  var accessUrl = panel.getAttribute("data-access-url");

  function desiredAccess() {
    var access = {};
    Array.prototype.forEach.call(
      panel.querySelectorAll("[data-key]"),
      function (el) {
        var key = el.getAttribute("data-key");
        var kind = el.getAttribute("data-kind");
        if (kind === "toggle") {
          access[key] = el.checked;
        } else if (kind === "select") {
          access[key] = el.value ? [el.value] : [];
        } else if (kind === "number") {
          var num = parseFloat(el.value);
          if (isFinite(num) && num >= 0) access[key] = num;
          else access[key] = null;
        } else {
          var values = [];
          Array.prototype.forEach.call(
            el.querySelectorAll("input[type=checkbox]"),
            function (box) {
              if (box.checked) values.push(box.getAttribute("data-value"));
            }
          );
          access[key] = values;
        }
      }
    );
    return access;
  }

  function saveAccess() {
    return fetch(accessUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": window.CSRF_TOKEN
          || (document.querySelector('meta[name="csrf-token"]') || {}).content
          || "",
      },
      body: JSON.stringify({ access: desiredAccess() }),
    }).then(function (resp) {
      if (!resp.ok) throw new Error("HTTP " + resp.status);
    }).catch(function (err) {
      // The server is the source of truth; a failed save leaves the panel
      // showing the admin's intent, not the stored state. A page reload
      // restores the stored state.
      console.error("access update failed", err);
    });
  }

  panel.addEventListener("change", function (e) {
    if (e.target.matches("[data-key], [data-key] input, [data-kind=multi] input")) {
      saveAccess();
    }
  });
  // A number field is edited continuously; save when it loses focus.
  panel.addEventListener("blur", function (e) {
    if (e.target.matches && e.target.matches("[data-kind=number]")) saveAccess();
  }, true);

  var roleSelect = document.querySelector("[data-role-select]");
  if (roleSelect) {
    roleSelect.addEventListener("change", function () {
      roleSelect.form.submit();
    });
  }

  // Deleting a user and purging their files are irreversible; the purge
  // asks twice because file deletion is harder to reverse than the account.

  function askTypedConfirm(title, body, username) {
    return new Promise(function (resolve) {
      var overlay = document.createElement("div");
      overlay.className = "pw-dialog-overlay";
      var box = document.createElement("div");
      box.className = "pw-dialog";
      var h = document.createElement("h2");
      h.textContent = title;
      box.appendChild(h);
      var p = document.createElement("p");
      p.textContent = body;
      box.appendChild(p);
      var label = document.createElement("label");
      label.textContent = "Type " + username + " to confirm";
      box.appendChild(label);
      var input = document.createElement("input");
      input.type = "text";
      input.autocomplete = "off";
      box.appendChild(input);
      var actions = document.createElement("div");
      actions.className = "pw-dialog-actions";
      var cancel = document.createElement("button");
      cancel.type = "button";
      cancel.className = "btn";
      cancel.textContent = "Cancel";
      var ok = document.createElement("button");
      ok.type = "button";
      ok.className = "btn btn-danger";
      ok.textContent = "Confirm";
      ok.disabled = true;
      actions.appendChild(cancel);
      actions.appendChild(ok);
      box.appendChild(actions);
      overlay.appendChild(box);
      document.body.appendChild(overlay);
      input.focus();

      function settle(value) {
        overlay.remove();
        document.removeEventListener("keydown", onKey, true);
        resolve(value);
      }
      function onKey(e) {
        if (e.key === "Escape") { e.stopPropagation(); settle(null); }
        else if (e.key === "Enter") { e.preventDefault(); settle(input.value); }
      }
      document.addEventListener("keydown", onKey, true);
      overlay.addEventListener("click", function (e) {
        if (e.target === overlay) settle(null);
      });
      input.addEventListener("input", function () {
        ok.disabled = input.value !== username;
      });
      cancel.addEventListener("click", function () { settle(null); });
      ok.addEventListener("click", function () { settle(input.value); });
    });
  }

  function bindTypedDelete(btn) {
    btn.addEventListener("click", function () {
      var username = btn.getAttribute("data-username");
      askTypedConfirm(
        "Delete " + username + "?",
        "This removes the account and all of the user's data. " +
        "It cannot be undone.",
        username
      ).then(function (value) {
        if (value === username) btn.form.submit();
      });
    });
  }

  var deleteBtn = document.querySelector("[data-delete-btn]");
  if (deleteBtn) bindTypedDelete(deleteBtn);

  var purgeBtn = document.querySelector("[data-purge-btn]");
  if (purgeBtn) {
    purgeBtn.addEventListener("click", function () {
      var username = purgeBtn.getAttribute("data-username");
      askTypedConfirm(
        "Delete all of " + username + "'s files?",
        "Every file the user has stored (uploads, model-created files, " +
        "and files inside their chats) will be permanently deleted. " +
        "The account itself stays.",
        username
      ).then(function (first) {
        if (first !== username) return;
        askTypedConfirm(
          "Really delete all of " + username + "'s files?",
          "This is the final confirmation: nothing can be recovered " +
          "afterwards.",
          username
        ).then(function (second) {
          if (second === username) {
            var form = purgeBtn.form;
            form.querySelector("input[name=confirm]").value = username;
            form.submit();
          }
        });
      });
    });
  }
})();
