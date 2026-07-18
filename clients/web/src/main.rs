//! Web-Client (Leptos, CSR): Einstiegspunkt.
//!
//! Der eigentliche Client lebt in `app.rs` und existiert nur für wasm32:
//! nativ gebaut (etwa von `cargo test --workspace`) bleibt ein erklärender
//! Stub, damit der Workspace-Lauf nicht am Browser-Code scheitert und
//! keine Browser-Abhängigkeiten für den Host kompilieren muss.

#[cfg(target_arch = "wasm32")]
mod app;
#[cfg(target_arch = "wasm32")]
mod push;
#[cfg(target_arch = "wasm32")]
mod storage;

#[cfg(target_arch = "wasm32")]
fn main() {
    app::run();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!(
        "sm-web ist der Browser-Client (wasm32-unknown-unknown); \
         bauen mit `trunk build` in clients/web (siehe Trunk.toml)."
    );
    std::process::exit(1);
}
