// VELFORT Phase 0.5/0.6 spike frontend (classic script). Runs automatically.
// Phase 0.6 (D-P13): withGlobalTauri=false, so window.__TAURI__ is absent. We call the same
// internal entry point that @tauri-apps/api 2.12.5 core.invoke uses (core.js: __TAURI_INTERNALS__.invoke).
// Canary values are generated at runtime so that no literal appears in this source file.
(function () {
  "use strict";
  const invoke = (cmd, args) => window.__TAURI_INTERNALS__.invoke(cmd, args || {});
  const out = {};
  const log = (k, v) => { out[k] = v; document.getElementById("log").textContent += k + ": " + JSON.stringify(v) + "\n"; };
  const rnd = () => Array.from(crypto.getRandomValues(new Uint8Array(6)), b => b.toString(16).padStart(2, "0")).join("");

  async function stage1() {
    // Option A: Master Password typed into a React-like uncontrolled input (simulated via insertText).
    const master = ["VELFORT", "CANARY", "MASTERJS", rnd()].join("-");
    const input = document.getElementById("pw");
    input.focus();
    document.execCommand("insertText", false, master);
    let value = input.value;                 // read once
    input.value = "";                        // clear the field immediately
    const n = await invoke("spike_unlock", { password: value });
    value = null;                            // drop our reference (no guarantee of wiping)
    log("unlock_len_ok", n === master.length);

    // Item secret revealed for display, then removed from DOM.
    const secret = await invoke("spike_reveal");
    const el = document.getElementById("reveal");
    el.textContent = secret;
    await new Promise(r => setTimeout(r, 300));
    el.textContent = "";

    // W6: a command registered in Rust but NOT in AppManifest/capability must be rejected.
    try { const r = await invoke("spike_forbidden"); log("forbidden_cmd", { allowed: true, value_len: String(r).length }); }
    catch (e) { log("forbidden_cmd", { allowed: false, error: String(e) }); }
    // Non-existent command.
    try { await invoke("does_not_exist"); log("unknown_cmd", { allowed: true }); }
    catch (e) { log("unknown_cmd", { allowed: false, error: String(e) }); }
    // Plugin command without capability (fs is not even compiled in).
    try { await invoke("plugin:fs|read_text_file", { path: "C:\\Windows\\win.ini" }); log("plugin_fs", { allowed: true }); }
    catch (e) { log("plugin_fs", { allowed: false, error: String(e) }); }

    // CSP: network egress must be blocked.
    try { await fetch("https://example.com/"); log("csp_fetch_external", { blocked: false }); }
    catch (e) { log("csp_fetch_external", { blocked: true, error: String(e) }); }
    // CSP: inline script must not execute.
    window.__inline_ran = false;
    const s = document.createElement("script"); s.textContent = "window.__inline_ran = true;"; document.body.appendChild(s);
    log("csp_inline_script_blocked", window.__inline_ran === false);
    // eval must be blocked (no 'unsafe-eval').
    try { eval("1+1"); log("csp_eval_blocked", false); } catch (e) { log("csp_eval_blocked", true); }

    log("isolation_hook_present_in_main_frame", typeof window.__TAURI_ISOLATION_HOOK__ !== "undefined");
    log("global_tauri_namespace_present", typeof window.__TAURI__ !== "undefined");
    log("tauri_internals_keys", Object.keys(window.__TAURI_INTERNALS__ || {}).sort());
    try { localStorage.setItem("velfort-ui-pref", "theme=dark"); log("localstorage_available", true); } catch (e) { log("localstorage_available", false); }

    await invoke("spike_phase", { phase: "before_reload", js: out });
    location.reload();
  }

  async function stage2() {
    await new Promise(r => setTimeout(r, 1500));
    await invoke("spike_phase", { phase: "after_reload", js: {} });
    // D-P10: renderer crash; Rust records dumps and exits ~10 s later.
    await invoke("spike_crash");
  }

  window.addEventListener("load", async () => {
    try {
      const st = await invoke("spike_stage");
      if (st === 0) await stage1(); else await stage2();
    } catch (e) {
      document.getElementById("log").textContent += "ERROR " + e;
      try { await invoke("spike_phase", { phase: "error", js: { error: String(e) } }); await invoke("spike_finish"); } catch (_) {}
    }
  });
})();
