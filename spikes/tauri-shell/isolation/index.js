// Isolation hook (classic script, no ES modules: they do not load in the sandboxed iframe on Windows).
// Spike: pass-through. A production hook would validate command names/shape here as a second layer.
window.__TAURI_ISOLATION_HOOK__ = (payload) => payload;
