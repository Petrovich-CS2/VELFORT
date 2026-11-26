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

#[tauri::command]
fn spike_finish(app: AppHandle, s: State<'_, Spike>) {
    let path = std::env::var("VELFORT_SPIKE_REPORT").unwrap_or_else(|_| "spike-report.json".into());
    let data_dir = app.path().app_local_data_dir().map(|p| p.display().to_string()).unwrap_or_default();
    let r = json!({
        "tauri": tauri::VERSION,
        "app_local_data_dir": data_dir,
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
        .invoke_handler(tauri::generate_handler![spike_stage, spike_unlock, spike_reveal, spike_forbidden, spike_phase, spike_finish])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
