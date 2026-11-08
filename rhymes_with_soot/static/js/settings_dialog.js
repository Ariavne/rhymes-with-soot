/* rhymes_with_soot — the auto-saving settings dialog (site-independent).
 *
 * A centered dialog listing the settings a site declares with
 * register_setting; every control saves itself on change (one PUT per
 * control, /api/settings/<key>) and flashes the per-row "Saved" note
 * (framework.css) on success or failure. Dismissed by Escape or a
 * backdrop click.
 *
 * Load it as an ES module and call openSettingsDialog(options):
 *
 *   import { openSettingsDialog } from "/static/js/settings_dialog.js";
 *   openSettingsDialog({ title: "Settings", onSaved: (key, value) => {} });
 *
 * Built-in row renderers cover the text, number, select, segment, and
 * toggle kinds; url and image_url fall back to a plain text input. A site
 * can supply its own control for any kind (for example an image picker)
 * with registerRowRenderer(kind, render);
 * render(def, value, ctx) returns the control element, and ctx.save(key,
 * value) persists it through the same flash + onSaved path.
 *
 * After each successful save the module fires a "settings:saved"
 * CustomEvent on document ({detail: {key, value}}) so page code can keep
 * its in-memory state in sync.
 */
"use strict";

const DEFS_URL = "/api/settings/defs";

// kind -> render(def, value, ctx) -> control element.
const rowRenderers = new Map();

export function registerRowRenderer(kind, render) {
  rowRenderers.set(kind, render);
}

let overlayEl = null;   // the open backdrop element, or null
let keyHandler = null;  // its Escape handler, or null
let onSaved = null;     // the open dialog's (key, value) callback

export function isSettingsDialogOpen() {
  return overlayEl !== null;
}

function csrfToken() {
  return window.CSRF_TOKEN || "";
}

function putSetting(key, value) {
  return fetch("/api/settings/" + key, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken(),
    },
    body: JSON.stringify({ value: value }),
  }).then(function (res) {
    if (!res.ok) throw new Error("settings update failed");
    return res.json();
  });
}

function flashSaved(row, ok) {
  const note = row.querySelector(".settings-saved");
  if (!note) return;
  note.textContent = ok ? "Saved" : "Save failed";
  note.classList.toggle("error", !ok);
  note.classList.remove("show");
  void note.offsetWidth; // restart the fade animation
  note.classList.add("show");
}

function save(key, value, row) {
  putSetting(key, value).then(function () {
    flashSaved(row, true);
    const cb = onSaved;
    if (cb) {
      try { cb(key, value); } catch (err) { console.error(err); }
    }
    document.dispatchEvent(new CustomEvent("settings:saved", {
      detail: { key: key, value: value },
    }));
  }).catch(function () {
    flashSaved(row, false);
  });
}

// Built-in row renderers

function makeControl(def, value, ctx) {
  const custom = rowRenderers.get(def.kind);
  if (custom) return custom(def, value, ctx);

  if (def.kind === "toggle") {
    const input = document.createElement("input");
    input.type = "checkbox";
    input.id = "set-" + def.key;
    input.checked = !!value;
    input.addEventListener("change", function () {
      ctx.save(def.key, input.checked);
    });
    return input;
  }

  if (def.kind === "select") {
    const input = document.createElement("select");
    input.id = "set-" + def.key;
    (def.choices || []).forEach(function (c) {
      const o = document.createElement("option");
      o.value = c[0];
      o.textContent = c[1];
      if (c[0] === value) o.selected = true;
      input.appendChild(o);
    });
    input.addEventListener("change", function () {
      ctx.save(def.key, input.value);
    });
    return input;
  }

  if (def.kind === "segment") {
    // A row of single-tap buttons over the choices (radio semantics).
    const group = document.createElement("div");
    group.className = "settings-segment";
    group.id = "set-" + def.key;
    group.setAttribute("role", "radiogroup");
    (def.choices || []).forEach(function (c) {
      const on = c[0] === value;
      const b = document.createElement("button");
      b.type = "button";
      b.className = "segment-btn" + (on ? " on" : "");
      b.setAttribute("role", "radio");
      b.setAttribute("aria-checked", on ? "true" : "false");
      b.textContent = c[1];
      b.addEventListener("click", function () {
        group.querySelectorAll(".segment-btn").forEach(function (o) {
          o.classList.remove("on");
          o.setAttribute("aria-checked", "false");
        });
        b.classList.add("on");
        b.setAttribute("aria-checked", "true");
        ctx.save(def.key, c[0]);
      });
      group.appendChild(b);
    });
    return group;
  }

  if (def.kind === "number") {
    const input = document.createElement("input");
    input.type = "number";
    input.id = "set-" + def.key;
    input.value = value == null ? "" : value;
    input.addEventListener("change", function () {
      const raw = input.value.trim();
      if (raw === "") {
        ctx.save(def.key, def.default == null ? null : Number(def.default));
        return;
      }
      const n = Number(raw);
      if (!Number.isInteger(n)) {
        input.value = value == null ? "" : value;
        return;
      }
      ctx.save(def.key, n);
    });
    return input;
  }

  // "text" and any kind without a registered renderer: a plain text input.
  const input = document.createElement("input");
  input.type = "text";
  input.id = "set-" + def.key;
  input.value = value == null ? "" : value;
  input.addEventListener("change", function () {
    ctx.save(def.key, input.value);
  });
  return input;
}

function makeRow(def, value) {
  const row = document.createElement("div");
  row.className = "settings-row";
  row.setAttribute("data-key", def.key);

  const ctx = {
    row: row,
    save: function (key, v) { save(key, v, row); },
  };
  const control = makeControl(def, value, ctx);

  const label = document.createElement("label");
  label.className = "settings-label";
  label.textContent = def.label;
  if (control.id && (control.tagName === "INPUT" || control.tagName === "SELECT")) {
    label.setAttribute("for", control.id);
  }

  row.appendChild(label);
  row.appendChild(control);

  const saved = document.createElement("span");
  saved.className = "settings-saved";
  saved.setAttribute("aria-live", "polite");
  row.appendChild(saved);

  if (def.help) {
    const hint = document.createElement("span");
    hint.className = "form-hint settings-hint";
    hint.textContent = def.help;
    row.appendChild(hint);
  }
  return row;
}

// Open / close

export function openSettingsDialog(options) {
  if (overlayEl) return;
  options = options || {};
  onSaved = options.onSaved || null;

  fetch(DEFS_URL).then(function (res) {
    if (!res.ok) throw new Error("load failed");
    return res.json();
  }).then(function (data) {
    const overlay = document.createElement("div");
    overlay.className = "settings-dialog-backdrop";
    const box = document.createElement("div");
    box.className = "settings-dialog";
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-modal", "true");
    box.setAttribute("aria-label", options.title || "Settings");

    const title = document.createElement("div");
    title.className = "settings-dialog-title";
    title.textContent = options.title || "Settings";
    box.appendChild(title);

    (data.defs || []).forEach(function (def) {
      const value = data.values && data.values[def.key] != null
        ? data.values[def.key] : def.default;
      box.appendChild(makeRow(def, value));
    });

    const actions = document.createElement("div");
    actions.className = "settings-dialog-actions";
    const close = document.createElement("button");
    close.type = "button";
    close.className = "btn btn-primary dialog-ok";
    close.textContent = "Done";
    close.addEventListener("click", closeSettingsDialog);
    actions.appendChild(close);
    box.appendChild(actions);

    overlay.appendChild(box);
    document.body.appendChild(overlay);
    overlayEl = overlay;

    keyHandler = function (e) {
      if (e.key !== "Escape") return;
      // A surface opened on top of the dialog (for example a picker) keeps
      // focus inside itself; let it handle Escape first.
      if (!overlayEl.contains(e.target)) return;
      e.stopPropagation();
      closeSettingsDialog();
    };
    document.addEventListener("keydown", keyHandler, true);
    overlay.addEventListener("click", function (e) {
      if (e.target === overlay) closeSettingsDialog();
    });
    close.focus();
  }).catch(function () {});
}

export function closeSettingsDialog() {
  if (overlayEl) {
    overlayEl.remove();
    overlayEl = null;
  }
  if (keyHandler) {
    document.removeEventListener("keydown", keyHandler, true);
    keyHandler = null;
  }
}
