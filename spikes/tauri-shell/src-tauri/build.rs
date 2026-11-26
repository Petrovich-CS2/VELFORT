fn main() {
    // Explicit allow-list of app commands (ARCHITECTURE §4.1 rule 2). `spike_forbidden` is registered
    // in invoke_handler but deliberately NOT listed here, so no permission exists for it.
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(
            tauri_build::AppManifest::new().commands(&["spike_stage", "spike_unlock", "spike_reveal", "spike_phase", "spike_finish", "spike_crash"]),
        ),
    )
    .expect("tauri build");
}
