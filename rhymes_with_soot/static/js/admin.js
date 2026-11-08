/* Admin page: the password dialog.
   Passwords are entered only inside the dialog's two inputs and submitted
   as a plain form POST — never in a URL, an attribute, or a JS variable.
   The rules below mirror the server's password policy; the server
   re-checks them and the two-entry match on every request. */
(function () {
  "use strict";

  var overlay = document.getElementById("pw-dialog");
  if (!overlay) return;

  var form = document.getElementById("pw-dialog-form");
  var usernameField = document.getElementById("pw-username");
  var roleField = document.getElementById("pw-role");
  var title = document.getElementById("pw-dialog-title");
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
    roleField.value = "user";
    pw1.value = "";
    pw2.value = "";
    if (mode === "create") {
      title.textContent = "Set password";
      usernameField.value = document.getElementById("new-username").value;
      roleField.value = document.getElementById("new-role").value;
      confirmBtn.textContent = "Set password";
    } else {
      title.textContent = "Reset password for " + username;
      confirmBtn.textContent = "Reset password";
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
  // Enter in the username/role fields routes through the dialog, too.
  createForm.addEventListener("submit", function (e) {
    e.preventDefault();
    trigger = createBtn;
    open("create", createForm.action, null);
  });

  Array.prototype.forEach.call(
    document.querySelectorAll(".reset-btn"),
    function (btn) {
      btn.addEventListener("click", function () {
        trigger = btn;
        open(
          "reset",
          btn.getAttribute("data-action"),
          btn.getAttribute("data-username")
        );
      });
    }
  );

  cancelBtn.addEventListener("click", close);
  pw1.addEventListener("input", update);
  pw2.addEventListener("input", update);
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !overlay.classList.contains("hidden")) close();
  });
  overlay.addEventListener("click", function (e) {
    if (e.target === overlay) close();
  });
})();
