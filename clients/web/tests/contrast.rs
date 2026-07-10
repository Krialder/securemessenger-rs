//! Kontrast-Abnahme der Design-Tokens (dokumentation/design-system.md).
//!
//! Dieser Test macht aus "barrierefrei" ein Kriterium statt einer
//! Behauptung: Er liest `theme.css` als einzige Quelle, extrahiert je Modus
//! (Hell, Dunkel, Midnight) die semantischen Tokens und rechnet für jedes
//! bedeutungstragende Farb-Paar das WCAG-2.x-Kontrastverhältnis nach.
//! Unterschreitet ein Paar in irgendeinem Modus seine Schwelle (4.5:1 für
//! Text, 3:1 für Nicht-Text nach SC 1.4.3 / 1.4.11), schlägt der Test fehl.
//!
//! Läuft nativ (kein WASM, keine Client-Abhängigkeiten) und damit in
//! `cargo test --workspace` mit. Die Kontrast-Mathematik ist die aus der
//! WCAG-Spezifikation, kein Eigenbau eines Farbmodells: relative Luminanz
//! mit sRGB-Linearisierung, Verhältnis (L1 + 0.05) / (L2 + 0.05).

use std::collections::HashMap;

const THEME_CSS: &str = include_str!("../theme.css");

/// Ein sRGB-Kanal (0..=255) linearisiert, wie in WCAG 2.x definiert.
fn linearize(channel: u8) -> f64 {
    let c = channel as f64 / 255.0;
    if c <= 0.04045 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

/// Relative Luminanz einer Farbe (WCAG 2.x Gewichte).
fn luminance((r, g, b): (u8, u8, u8)) -> f64 {
    0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b)
}

/// Kontrastverhältnis zweier Farben; heller Wert oben, Ergebnis >= 1.0.
fn contrast(a: (u8, u8, u8), b: (u8, u8, u8)) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    let (hi, lo) = if la >= lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

fn parse_hex(hex: &str) -> (u8, u8, u8) {
    let hex = hex.trim_start_matches('#');
    let byte = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).expect("gültiges Hex");
    (byte(0), byte(2), byte(4))
}

/// Liest die `--sm-*: #rrggbb;`-Zuweisungen aus dem Block eines Selektors.
/// Die Theme-Blöcke enthalten keine verschachtelten Klammern, deshalb reicht
/// die erste schließende Klammer nach dem Selektor.
fn parse_theme(selector: &str) -> HashMap<String, (u8, u8, u8)> {
    let start = THEME_CSS
        .find(selector)
        .unwrap_or_else(|| panic!("Selektor '{selector}' fehlt in theme.css"));
    let open = THEME_CSS[start..].find('{').expect("Blockanfang") + start;
    let close = THEME_CSS[open..].find('}').expect("Blockende") + open;
    let block = &THEME_CSS[open + 1..close];

    let mut tokens = HashMap::new();
    for line in block.lines() {
        let line = line.trim().trim_end_matches(';');
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if let Some(key) = name.strip_prefix("--sm-") {
            if value.starts_with('#') && value.len() == 7 {
                tokens.insert(key.to_string(), parse_hex(value));
            }
        }
    }
    tokens
}

/// Ein zu prüfendes Farb-Paar: Vordergrund auf Hintergrund, Mindestkontrast.
struct Pair {
    fg: &'static str,
    bg: &'static str,
    min: f64,
    reason: &'static str,
}

const PAIRS: &[Pair] = &[
    // Text (SC 1.4.3, 4.5:1).
    Pair {
        fg: "on-surface",
        bg: "surface",
        min: 4.5,
        reason: "Fließtext",
    },
    Pair {
        fg: "on-surface-muted",
        bg: "surface",
        min: 4.5,
        reason: "gedämpfter Text (Metadaten)",
    },
    Pair {
        fg: "on-primary",
        bg: "primary",
        min: 4.5,
        reason: "Text auf Primärknopf",
    },
    Pair {
        fg: "primary",
        bg: "surface",
        min: 4.5,
        reason: "Akzent/Link als Text",
    },
    Pair {
        fg: "success",
        bg: "surface",
        min: 4.5,
        reason: "Erfolgsmeldung",
    },
    Pair {
        fg: "danger",
        bg: "surface",
        min: 4.5,
        reason: "Warnung/Alarm",
    },
    Pair {
        fg: "warning",
        bg: "surface",
        min: 4.5,
        reason: "Vorsichtshinweis",
    },
    Pair {
        fg: "on-surface",
        bg: "bubble-in",
        min: 4.5,
        reason: "Text in Empfangs-Blase",
    },
    Pair {
        fg: "on-surface",
        bg: "bubble-out",
        min: 4.5,
        reason: "Text in Sende-Blase",
    },
    Pair {
        fg: "notify-on",
        bg: "notify-surface",
        min: 4.5,
        reason: "Benachrichtigungstext",
    },
    // Konversationsliste und Auswahl (Text, SC 1.4.3, 4.5:1).
    Pair {
        fg: "on-selected",
        bg: "selected",
        min: 4.5,
        reason: "Name auf ausgewählter Zeile",
    },
    Pair {
        fg: "on-selected-muted",
        bg: "selected",
        min: 4.5,
        reason: "Auszug/Zeit auf ausgewählter Zeile",
    },
    Pair {
        fg: "on-unread-badge",
        bg: "unread-badge",
        min: 4.5,
        reason: "Zahl in der Ungelesen-Pille",
    },
    // Sicherheits-Badges im Chat-Kopf (Text auf der Kopfleiste).
    Pair {
        fg: "verified",
        bg: "surface-container",
        min: 4.5,
        reason: "Status verglichen",
    },
    Pair {
        fg: "unverified",
        bg: "surface-container",
        min: 4.5,
        reason: "Status nicht verglichen",
    },
    Pair {
        fg: "ttl",
        bg: "surface-container",
        min: 4.5,
        reason: "Frist-Anzeige",
    },
    // Avatar-Initialen auf den sechs Palettenfarben (Text, 4.5:1).
    Pair {
        fg: "avatar-1",
        bg: "avatar-on",
        min: 4.5,
        reason: "Avatar-Initiale 1",
    },
    Pair {
        fg: "avatar-2",
        bg: "avatar-on",
        min: 4.5,
        reason: "Avatar-Initiale 2",
    },
    Pair {
        fg: "avatar-3",
        bg: "avatar-on",
        min: 4.5,
        reason: "Avatar-Initiale 3",
    },
    Pair {
        fg: "avatar-4",
        bg: "avatar-on",
        min: 4.5,
        reason: "Avatar-Initiale 4",
    },
    Pair {
        fg: "avatar-5",
        bg: "avatar-on",
        min: 4.5,
        reason: "Avatar-Initiale 5",
    },
    Pair {
        fg: "avatar-6",
        bg: "avatar-on",
        min: 4.5,
        reason: "Avatar-Initiale 6",
    },
    // Nicht-Text (SC 1.4.11, 3:1).
    Pair {
        fg: "border",
        bg: "surface",
        min: 3.0,
        reason: "Eingabefeld-Rahmen",
    },
    Pair {
        fg: "focus",
        bg: "surface",
        min: 3.0,
        reason: "Fokusring",
    },
    Pair {
        fg: "sealed",
        bg: "surface-container",
        min: 3.0,
        reason: "Sealed-Symbol (dekorativ)",
    },
    // Ungelesen-Pille als Grafik gegen alle drei Zeilenzustände (3:1).
    Pair {
        fg: "unread-badge",
        bg: "surface-container",
        min: 3.0,
        reason: "Pille auf normaler Zeile",
    },
    Pair {
        fg: "unread-badge",
        bg: "list-hover",
        min: 3.0,
        reason: "Pille auf Hover-Zeile",
    },
    Pair {
        fg: "unread-badge",
        bg: "selected",
        min: 3.0,
        reason: "Pille auf ausgewählter Zeile",
    },
];

const THEMES: &[(&str, &str)] = &[
    ("Hell", "[data-theme=\"hell\"]"),
    ("Dunkel", "[data-theme=\"dunkel\"]"),
    ("Midnight", "[data-theme=\"midnight\"]"),
];

#[test]
fn every_token_pair_meets_wcag_in_every_theme() {
    let mut failures = Vec::new();
    for (theme_name, selector) in THEMES {
        let tokens = parse_theme(selector);
        for pair in PAIRS {
            let fg = tokens
                .get(pair.fg)
                .unwrap_or_else(|| panic!("Token --sm-{} fehlt im Modus {theme_name}", pair.fg));
            let bg = tokens
                .get(pair.bg)
                .unwrap_or_else(|| panic!("Token --sm-{} fehlt im Modus {theme_name}", pair.bg));
            let ratio = contrast(*fg, *bg);
            if ratio < pair.min {
                failures.push(format!(
                    "{theme_name}: {} auf {} ({}) = {ratio:.2}:1, gefordert {:.1}:1",
                    pair.fg, pair.bg, pair.reason, pair.min
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "Kontrast-Untergrenzen verletzt:\n{}",
        failures.join("\n")
    );
}

#[test]
fn contrast_math_matches_known_values() {
    // Ankerwerte gegen die WCAG-Referenz: Schwarz auf Weiß ist 21:1, eine
    // Farbe gegen sich selbst 1:1. Fängt einen kaputten Rechenweg ab, bevor
    // er die Token-Prüfung still bestehen lässt.
    assert!((contrast((0, 0, 0), (255, 255, 255)) - 21.0).abs() < 0.01);
    assert!((contrast((18, 18, 18), (18, 18, 18)) - 1.0).abs() < 0.001);
    // #767680 auf #fbfbfd liegt bekannt knapp über 3:1 (Nicht-Text-Grenze).
    assert!(contrast((0x76, 0x76, 0x80), (0xfb, 0xfb, 0xfd)) > 3.0);
}
