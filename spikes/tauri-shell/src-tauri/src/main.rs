//! VELFORT Phase 0.5 spike shell (W5/W6/W7). NOT the application.
//! Writes a JSON report to %VELFORT_SPIKE_REPORT% (or ./spike-report.json) and exits.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde_json::{Value, json};
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroize;

#[derive(Default)]
struct Spike {
    stage: Mutex<u8>,
    /// Needles for memory scanning. Keeping copies here is a deliberate test artefact.
    master: Mutex<String>,
    item: Mutex<String>,
    report: Mutex<Vec<Value>>,
    webview2: Mutex<Value>,
    crash: Mutex<Value>,
}

#[tauri::command]
fn spike_stage(s: State<'_, Spike>) -> u8 {
    let mut st = s.stage.lock().unwrap();
    let v = *st;
    *st = 1;
    v
}

#[tauri::command]
fn spike_unlock(password: String, s: State<'_, Spike>) -> usize {
    let n = password.len();
    *s.master.lock().unwrap() = password.clone(); // test artefact (needle)
    let mut p = password;
    p.zeroize(); // our own copy is wiped; IPC/serde copies are not under our control
    n
}

#[tauri::command]
fn spike_reveal(s: State<'_, Spike>) -> String {
    let mut b = [0u8; 6];
    let _ = getrandom_hex(&mut b);
    let v = format!("VELFORT-CANARY-ITEMPW-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>());
    *s.item.lock().unwrap() = v.clone();
    v
}

fn getrandom_hex(b: &mut [u8]) -> Result<(), ()> {
    // Spike: system time based uniqueness is sufficient for a canary.
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| ())?.as_nanos();
    for (i, x) in b.iter_mut().enumerate() {
        *x = (t >> (i * 8)) as u8;
    }
    Ok(())
}

/// Registered in invoke_handler but NOT in AppManifest::commands => no permission => must be denied.
#[tauri::command]
fn spike_forbidden() -> String {
    "THIS-VALUE-MUST-NOT-REACH-JS".into()
}

#[cfg(windows)]
fn scan(s: &Spike) -> Value {
    use win_memory::scan::{pids_by_name, scan_process, utf16le};
    let m = s.master.lock().unwrap().clone();
    let i = s.item.lock().unwrap().clone();
    let needles = vec![utf16le(&m), m.as_bytes().to_vec(), utf16le(&i), i.as_bytes().to_vec()];
    let mut procs = Vec::new();
    for pid in pids_by_name("msedgewebview2.exe") {
        procs.push(json!({"pid": pid, "exe": "msedgewebview2.exe", "counts[master16,master8,item16,item8]": scan_process(pid, &needles)}));
    }
    procs.push(json!({"pid": std::process::id(), "exe": "self (Rust; holds needle copies by design)", "counts[master16,master8,item16,item8]": scan_process(std::process::id(), &needles)}));
    Value::Array(procs)
}
#[cfg(not(windows))]
fn scan(_s: &Spike) -> Value {
    json!("memory scan only implemented on Windows")
}

#[tauri::command]
fn spike_phase(phase: String, js: Value, s: State<'_, Spike>) {
    let mem = scan(&s);
    s.report.lock().unwrap().push(json!({"phase": phase, "js": js, "memory": mem}));
}

/// Reads WebView2 settings BEFORE touching them (to verify the Tauri config path), then sets
/// password autosave and general autofill to false explicitly and reads them back; also reads
/// FailureReportFolderPath (ICoreWebView2Environment11).
#[cfg(windows)]
#[allow(unsafe_code)]
fn webview2_probe(pv: tauri::webview::PlatformWebview) -> Value {
    use webview2_com::Microsoft::Web::WebView2::Win32::{ICoreWebView2Environment11, ICoreWebView2Settings4};
    use windows_core::{BOOL, Interface, PWSTR};
    let mut r = serde_json::Map::new();
    // SAFETY: COM calls on interfaces obtained from the live controller, on the main thread.
    unsafe {
        match pv.controller().CoreWebView2().and_then(|c| c.Settings()).and_then(|s| s.cast::<ICoreWebView2Settings4>()) {
            Ok(s4) => {
                let read = |s4: &ICoreWebView2Settings4| {
                    let (mut a, mut b) = (BOOL(-1), BOOL(-1));
                    let ra = s4.IsPasswordAutosaveEnabled(&mut a).is_ok();
                    let rb = s4.IsGeneralAutofillEnabled(&mut b).is_ok();
                    json!({"password_autosave": if ra { json!(a.as_bool()) } else { json!("read error") },
                           "general_autofill": if rb { json!(b.as_bool()) } else { json!("read error") }})
                };
                r.insert("before_explicit_set (config + WebView2 defaults)".into(), read(&s4));
                let set_a = s4.SetIsPasswordAutosaveEnabled(false).is_ok();
                let set_b = s4.SetIsGeneralAutofillEnabled(false).is_ok();
                r.insert("explicit_set_ok".into(), json!({"password_autosave": set_a, "general_autofill": set_b}));
                r.insert("after_explicit_set".into(), read(&s4));
            }
            Err(e) => {
                r.insert("settings4".into(), json!(format!("unavailable: {e}")));
            }
        }
        match pv.environment().cast::<ICoreWebView2Environment11>() {
            Ok(env) => {
                let mut p = PWSTR::null();
                if env.FailureReportFolderPath(&mut p).is_ok() && !p.is_null() {
                    r.insert("failure_report_folder".into(), json!(p.to_string().unwrap_or_default()));
                    windows::Win32::System::Com::CoTaskMemFree(Some(p.0 as _));
                } else {
                    r.insert("failure_report_folder".into(), json!("read error"));
                }
            }
            Err(e) => {
                r.insert("failure_report_folder".into(), json!(format!("Environment11 unavailable: {e}")));
            }
        }
    }
    Value::Object(r)
}

/// Lists every file under `dir` with size and scans it for the canaries (UTF-8 and UTF-16LE).
fn scan_dir_for(dir: &std::path::Path, needles: &[String]) -> Value {
    fn walk(p: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let q = e.path();
                if q.is_dir() { walk(&q, out) } else { out.push(q) }
            }
        }
    }
    let mut files = Vec::new();
    walk(dir, &mut files);
    let mut list = Vec::new();
    for f in &files {
        let data = std::fs::read(f).unwrap_or_default();
        let mut hits = Vec::new();
        for n in needles {
            if n.is_empty() {
                continue;
            }
            let u8n = n.as_bytes();
            let u16n: Vec<u8> = n.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            let c8 = data.windows(u8n.len()).filter(|w| *w == u8n).count();
            let c16 = data.windows(u16n.len()).filter(|w| *w == &u16n[..]).count();
            hits.push(json!([c8, c16]));
        }
        list.push(json!({"file": f.display().to_string(), "bytes": data.len(), "hits[master,item] as [utf8,utf16]": hits}));
    }
    json!({"dir": dir.display().to_string(), "files": list})
}

/// Forces a renderer crash via the DevTools protocol (`Page.crash`) and, from a background
/// thread, records dump files and their canary content before writing the report and exiting.
#[tauri::command]
#[allow(unsafe_code)]
fn spike_crash(app: AppHandle, s: State<'_, Spike>) {
    #[cfg(windows)]
    {
        use webview2_com::CallDevToolsProtocolMethodCompletedHandler;
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.with_webview(|pv| {
                // SAFETY: COM call on the live controller's CoreWebView2 on the main thread.
                unsafe {
                    if let Ok(core) = pv.controller().CoreWebView2() {
                        let h = CallDevToolsProtocolMethodCompletedHandler::create(Box::new(|_hr, _json| Ok(())));
                        let _ = core.CallDevToolsProtocolMethod(windows_core::w!("Page.crash"), windows_core::w!("{}"), &h);
                    }
                }
            });
        }
    }
    *s.crash.lock().unwrap() = json!({"requested": "Page.crash", "at_unix": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)});
    let app2 = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(10));
        finish(&app2);
    });
}

#[tauri::command]
fn spike_finish(app: AppHandle) {
    finish(&app);
}

fn finish(app: &AppHandle) {
    let s = app.state::<Spike>();
    let path = std::env::var("VELFORT_SPIKE_REPORT").unwrap_or_else(|_| "spike-report.json".into());
    let data_dir = app.path().app_local_data_dir().map(|p| p.display().to_string()).unwrap_or_default();
    let needles = vec![s.master.lock().unwrap().clone(), s.item.lock().unwrap().clone()];
    let wv = s.webview2.lock().unwrap().clone();
    let dump_dirs: Vec<Value> = [wv.get("failure_report_folder").and_then(|v| v.as_str()).map(String::from), Some(format!("{data_dir}\\EBWebView\\Crashpad"))]
        .into_iter()
        .flatten()
        .map(|d| scan_dir_for(std::path::Path::new(&d), &needles))
        .collect();
    let r = json!({
        "tauri": tauri::VERSION,
        "app_local_data_dir": data_dir,
        "webview2_settings_and_paths": wv,
        "crash_test": *s.crash.lock().unwrap(),
        "dump_dirs_after_crash": dump_dirs,
        "canary_master": *s.master.lock().unwrap(),
        "canary_item": *s.item.lock().unwrap(),
        "phases": *s.report.lock().unwrap(),
    });
    let _ = std::fs::write(&path, serde_json::to_vec_pretty(&r).unwrap());
    app.exit(0);
}

fn main() {
    tauri::Builder::default()
        .manage(Spike::default())
        .setup(|app| {
            #[cfg(windows)]
            if let Some(w) = app.get_webview_window("main") {
                let h = app.handle().clone();
                let _ = w.with_webview(move |pv| {
                    let v = webview2_probe(pv);
                    *h.state::<Spike>().webview2.lock().unwrap() = v;
                });
            }
            let _ = app;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![spike_stage, spike_unlock, spike_reveal, spike_forbidden, spike_phase, spike_finish, spike_crash])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
