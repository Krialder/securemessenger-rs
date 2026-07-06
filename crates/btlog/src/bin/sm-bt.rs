//! `sm-bt`: das Kommandozeilen-Werkzeug zum Binary-Transparency-Log.
//!
//! Dünne Schale über der btlog-Bibliothek: sie liest und schreibt die
//! beiden Dateien eines Log-Verzeichnisses (`log.jsonl`, `head.json`) und
//! übersetzt zwischen Umgebung und Bibliothek. Die Fachlogik (Kette,
//! Signatur, Prüfung) liegt vollständig in der Bibliothek und ist dort
//! getestet; hier gibt es nichts zu beweisen außer Ein-/Ausgabe.
//!
//! Befehle:
//!   sm-bt append <log-verzeichnis> <artefaktname> <version> <datei>
//!       hasht die Datei und traegt sie ein (BT_SIGNING_KEY, Base64-Seed)
//!   sm-bt verify <log-verzeichnis>
//!       prueft Kette und Kopf-Signatur (BT_PUBLIC_KEY, Base64, 32 Bytes)
//!   sm-bt list <log-verzeichnis>
//!       zeigt die Eintraege
//!   sm-bt lookup <log-verzeichnis> <datei>
//!       hasht die Datei und sucht sie im Log (der Client-Blick: "ist
//!       mein Binary das veroeffentlichte?")

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

fn main() {
    if let Err(error) = run() {
        eprintln!("Fehler: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str).unwrap_or("help") {
        "append" => append(&args[1..]),
        "verify" => verify(&args[1..]),
        "list" => list(&args[1..]),
        "lookup" => lookup(&args[1..]),
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => {
            print_usage();
            Err(format!("unbekannter Befehl: {other}"))
        }
    }
}

fn print_usage() {
    eprintln!(
        "sm-bt - Binary-Transparency-Log (ADR-0007)\n\
         Befehle:\n\
         \x20 append <log-dir> <artefakt> <version> <datei>   Datei hashen und eintragen (BT_SIGNING_KEY)\n\
         \x20 verify <log-dir>                                Kette und Kopf-Signatur pruefen (BT_PUBLIC_KEY)\n\
         \x20 list <log-dir>                                  Eintraege zeigen\n\
         \x20 lookup <log-dir> <datei>                        Datei hashen und im Log suchen\n\
         Umgebung:\n\
         \x20 BT_SIGNING_KEY      Base64, 32-Byte-Seed des Ed25519-Signierschluessels\n\
         \x20 BT_PUBLIC_KEY       Base64, 32 Bytes; alternativ genuegt BT_SIGNING_KEY\n\
         \x20 SOURCE_DATE_EPOCH   Bauzeitpunkt (Unix-Sekunden); ohne: aktuelle Zeit"
    );
}

fn log_paths(dir: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let base = std::path::Path::new(dir);
    (base.join("log.jsonl"), base.join("head.json"))
}

fn load_entries(dir: &str) -> Result<Vec<btlog::LogEntry>, String> {
    let (log_path, _) = log_paths(dir);
    if !log_path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
    btlog::from_jsonl(&text).map_err(|e| e.to_string())
}

fn load_head(dir: &str) -> Result<btlog::LogHead, String> {
    let (_, head_path) = log_paths(dir);
    let text = std::fs::read_to_string(&head_path)
        .map_err(|_| format!("{} fehlt; noch kein Eintrag?", head_path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("Kopf unlesbar: {e}"))
}

fn file_sha256(path: &str) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    Ok(Sha256::digest(&bytes).into())
}

fn signing_key() -> Result<ed25519_dalek::SigningKey, String> {
    let seed_b64 = std::env::var("BT_SIGNING_KEY")
        .map_err(|_| "BT_SIGNING_KEY nicht gesetzt (Base64, 32-Byte-Seed)".to_string())?;
    let seed = BASE64
        .decode(seed_b64.trim())
        .map_err(|_| "BT_SIGNING_KEY ist kein Base64".to_string())?;
    btlog::signing_key_from_seed(&seed).map_err(|e| e.to_string())
}

/// Der Prüfschlüssel: BT_PUBLIC_KEY, oder aus BT_SIGNING_KEY abgeleitet
/// (bequem auf der Maschine, die ohnehin signiert).
fn verifying_key() -> Result<ed25519_dalek::VerifyingKey, String> {
    if let Ok(public_b64) = std::env::var("BT_PUBLIC_KEY") {
        let raw = BASE64
            .decode(public_b64.trim())
            .map_err(|_| "BT_PUBLIC_KEY ist kein Base64".to_string())?;
        return btlog::verifying_key_from_bytes(&raw).map_err(|e| e.to_string());
    }
    Ok(signing_key()
        .map_err(|_| "weder BT_PUBLIC_KEY noch BT_SIGNING_KEY gesetzt".to_string())?
        .verifying_key())
}

fn append(args: &[String]) -> Result<(), String> {
    let [dir, artifact, version, file] = args else {
        return Err("Aufruf: sm-bt append <log-dir> <artefakt> <version> <datei>".to_string());
    };
    let signer = signing_key()?;
    let entries = load_entries(dir)?;

    // Vor dem Anhängen die vorhandene Kopie prüfen: ein korruptes Log
    // weiterzuschreiben würde den Schaden nur verstecken.
    if !entries.is_empty() {
        let head = load_head(dir)?;
        btlog::verify(&entries, &head, &signer.verifying_key())
            .map_err(|e| format!("vorhandenes Log ist ungültig, breche ab: {e}"))?;
    }

    let sha256 = file_sha256(file)?;
    let built_at = built_at()?;
    let (entry, head) = btlog::append(&entries, artifact, version, &sha256, built_at, &signer)
        .map_err(|e| e.to_string())?;

    let (log_path, head_path) = log_paths(dir);
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut all = entries;
    all.push(entry.clone());
    write_atomically(
        &log_path,
        btlog::to_jsonl(&all).map_err(|e| e.to_string())?.as_bytes(),
    )?;
    write_atomically(
        &head_path,
        serde_json::to_string_pretty(&head)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )?;

    println!(
        "Eintrag {}: {} {} ({})",
        entry.index, entry.artifact, entry.version, entry.sha256
    );
    Ok(())
}

/// Der Bauzeitpunkt des Eintrags: `SOURCE_DATE_EPOCH` (die Konvention der
/// Reproducible-Builds-Welt, die CI ohnehin setzt), sonst die aktuelle
/// Zeit. So erfindet das Log keine Bauzeit, wenn der Aufrufer die echte
/// kennt, und ein Nachtrag alter Releases protokolliert den richtigen
/// Zeitpunkt statt des Nachtrags-Moments.
fn built_at() -> Result<u64, String> {
    if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        return epoch
            .trim()
            .parse::<u64>()
            .map_err(|_| "SOURCE_DATE_EPOCH ist keine Unix-Sekundenzahl".to_string());
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| e.to_string())
}

/// Schreibt eine Datei über eine Temp-Datei plus Rename (auf Windows
/// ersetzt `fs::rename` ein vorhandenes Ziel). Ein Absturz mitten im
/// Schreiben hinterlässt so nie eine halbe Datei; das kleine Fenster
/// zwischen den beiden Renames von Log und Kopf bleibt, ist aber
/// fail-closed: verify meldet den Versatz, nichts wird fälschlich gültig.
fn write_atomically(path: &std::path::Path, contents: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

fn verify(args: &[String]) -> Result<(), String> {
    let [dir] = args else {
        return Err("Aufruf: sm-bt verify <log-dir>".to_string());
    };
    let entries = load_entries(dir)?;
    let head = load_head(dir)?;
    let public = verifying_key()?;
    btlog::verify(&entries, &head, &public).map_err(|e| e.to_string())?;
    println!(
        "Log ist gültig: {} Eintrag/Einträge, Kette und Kopf-Signatur stimmen.",
        entries.len()
    );
    Ok(())
}

fn list(args: &[String]) -> Result<(), String> {
    let [dir] = args else {
        return Err("Aufruf: sm-bt list <log-dir>".to_string());
    };
    let entries = load_entries(dir)?;
    if entries.is_empty() {
        println!("Log ist leer.");
        return Ok(());
    }
    for entry in &entries {
        println!(
            "{:>4}  {}  {}  {}  built_at={}",
            entry.index, entry.artifact, entry.version, entry.sha256, entry.built_at
        );
    }
    Ok(())
}

fn lookup(args: &[String]) -> Result<(), String> {
    let [dir, file] = args else {
        return Err("Aufruf: sm-bt lookup <log-dir> <datei>".to_string());
    };
    let entries = load_entries(dir)?;
    let sha256 = file_sha256(file)?;
    match btlog::find_by_sha256(&entries, &sha256) {
        Some(entry) => {
            println!(
                "Im Log: Eintrag {} ({} {})",
                entry.index, entry.artifact, entry.version
            );
            Ok(())
        }
        None => Err(format!(
            "NICHT im Log: {} (SHA-256 {})",
            file,
            BASE64.encode(sha256)
        )),
    }
}
