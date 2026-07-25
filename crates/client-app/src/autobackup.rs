//! Regeln der automatischen Sicherung: WANN wird die Sicherungsdatei neu
//! geschrieben, und wann rotiert dabei der Konto-Wurzelschlüssel.
//!
//! Die Sicherungsdatei (`backup`-Modul, `smbak.v1`) trägt den gesamten
//! Geräte-Zustand. Von Hand exportiert veraltet sie schnell: nach jeder neuen
//! Gruppe, jedem gekoppelten Gerät, jedem Ratchet-Schritt ist der Stand in der
//! Datei älter als der im Gerät. Diese Regeln automatisieren das Nachziehen.
//!
//! Die Auslöser sind KOMBINIERBAR (der Nutzer wählt mehrere), denn sie deckén
//! verschiedene Verlust-Fälle ab: das Intervall fängt den Absturz, das
//! Verlassen der Seite den geordneten Schluss, und der Nachrichten-Auslöser
//! hält den Stand bei aktivem Gebrauch frisch. Je Auslöser lässt sich
//! getrennt bestimmen, ob dabei auch der Konto-Wurzelschlüssel rotiert; so
//! kann man etwa stündlich sichern, aber nur beim Verlassen rotieren.
//!
//! Die Rotation ist bewusst gedrosselt (`rotation_min_gap_secs`): sie ersetzt
//! den Wurzelschlüssel des Kontos und ändert damit die Sicherheitsnummer bei
//! JEDEM Kontakt, was dort die Schlüsselwechsel-Warnung auslöst. Bei jeder
//! empfangenen Nachricht zu rotieren würde diese Warnung zum Dauerzustand
//! machen, also genau den Alarm abstumpfen, der eine Kompromittierung
//! anzeigen soll. Die Voreinstellung ist deshalb höchstens einmal pro Tag.

use serde::{Deserialize, Serialize};

/// Was eine Sicherung auslöst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    /// Nach einem Zeitabstand (siehe `interval_secs`), solange die App offen
    /// ist.
    Interval,
    /// Beim Verlassen der Seite (Tab-Wechsel, Minimieren, Schließen).
    ///
    /// [ANNAHME: Der Browser gibt beim Schließen nur ein sehr kurzes Zeitfenster
    /// und bricht asynchrone Arbeit oft ab; ein Blockieren des Schließens ist
    /// nicht möglich (und von den Browsern absichtlich abgeschafft). Deshalb
    /// wird bei JEDEM Sichtbarkeitswechsel geschrieben, nicht erst beim
    /// endgültigen Schließen: dann ist der Stand praktisch immer aktuell, auch
    /// wenn der letzte Schreibvorgang einmal abbricht.]
    PageHide,
    /// Nach dem Empfang einer Nachricht (der Ratchet ist weitergelaufen, der
    /// Stand in der Datei damit veraltet).
    MessageReceived,
}

impl Trigger {
    /// Alle Auslöser, für die Anzeige in den Einstellungen.
    pub const ALL: [Trigger; 3] = [
        Trigger::Interval,
        Trigger::PageHide,
        Trigger::MessageReceived,
    ];

    /// Beschriftung für die Oberfläche.
    pub fn label(self) -> &'static str {
        match self {
            Trigger::Interval => "Nach Zeitabstand",
            Trigger::PageHide => "Beim Verlassen der Seite",
            Trigger::MessageReceived => "Nach empfangener Nachricht",
        }
    }
}

/// Voreinstellung des Zeitabstands: eine Stunde. Häufig genug, dass wenig
/// verloren geht, selten genug, dass das Schreiben nicht auffällt.
pub const DEFAULT_INTERVAL_SECS: u64 = 3600;

/// Untergrenze des Zeitabstands. Jede Sicherung leitet den Datei-Schlüssel per
/// Argon2 neu ab (bewusst teuer), ein Sekundentakt wäre also spürbar und ohne
/// Nutzen.
pub const MIN_INTERVAL_SECS: u64 = 60;

/// Voreinstellung der Rotations-Drossel: höchstens einmal pro Tag (Begründung
/// im Modul-Kommentar).
pub const DEFAULT_ROTATION_MIN_GAP_SECS: u64 = 86_400;

/// Die Einstellungen der automatischen Sicherung. Liegen im verschlüsselten
/// Zustands-Blob des Geräts, nicht beim Dienst.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoBackup {
    /// Aktive Auslöser. Leer heißt: keine automatische Sicherung.
    #[serde(default)]
    pub triggers: Vec<Trigger>,
    /// Auslöser, bei denen zusätzlich der Konto-Wurzelschlüssel rotiert.
    /// Immer eine Teilmenge von `triggers` (siehe [`AutoBackup::normalize`]).
    #[serde(default)]
    pub rotate_on: Vec<Trigger>,
    /// Zeitabstand für [`Trigger::Interval`] in Sekunden.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Mindestabstand zwischen zwei Wurzelrotationen in Sekunden. 0 hebt die
    /// Drossel auf (nicht empfohlen, siehe Modul-Kommentar).
    #[serde(default = "default_rotation_gap")]
    pub rotation_min_gap_secs: u64,
}

fn default_interval() -> u64 {
    DEFAULT_INTERVAL_SECS
}

fn default_rotation_gap() -> u64 {
    DEFAULT_ROTATION_MIN_GAP_SECS
}

impl Default for AutoBackup {
    fn default() -> Self {
        Self {
            triggers: Vec::new(),
            rotate_on: Vec::new(),
            interval_secs: DEFAULT_INTERVAL_SECS,
            rotation_min_gap_secs: DEFAULT_ROTATION_MIN_GAP_SECS,
        }
    }
}

/// Was bei einem Auslöser zu tun ist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nichts tun (Auslöser nicht aktiv, oder das Intervall ist noch nicht um).
    Skip,
    /// Sicherung schreiben.
    Backup,
    /// Sicherung schreiben und vorher den Wurzelschlüssel rotieren.
    BackupWithRotation,
}

impl AutoBackup {
    /// Ob überhaupt etwas automatisch passiert.
    pub fn is_active(&self) -> bool {
        !self.triggers.is_empty()
    }

    pub fn has(&self, trigger: Trigger) -> bool {
        self.triggers.contains(&trigger)
    }

    pub fn rotates_on(&self, trigger: Trigger) -> bool {
        self.rotate_on.contains(&trigger)
    }

    /// Räumt die Einstellungen auf, bevor sie abgelegt werden: Duplikate raus,
    /// `rotate_on` auf die aktiven Auslöser beschränken (ein Rotations-Haken
    /// ohne zugehörigen Auslöser hätte keine Wirkung und wäre in der
    /// Oberfläche irreführend), und den Zeitabstand auf die Untergrenze heben.
    pub fn normalize(&mut self) {
        self.triggers.dedup();
        self.triggers = Trigger::ALL
            .iter()
            .copied()
            .filter(|t| self.triggers.contains(t))
            .collect();
        self.rotate_on = Trigger::ALL
            .iter()
            .copied()
            .filter(|t| self.rotate_on.contains(t) && self.triggers.contains(t))
            .collect();
        if self.interval_secs < MIN_INTERVAL_SECS {
            self.interval_secs = MIN_INTERVAL_SECS;
        }
    }

    /// Entscheidet, was ein Auslöser jetzt bewirkt.
    ///
    /// `now` ist die aktuelle Zeit in Unix-Sekunden, `last_backup` und
    /// `last_rotation` die Zeitpunkte der letzten Sicherung bzw. Rotation
    /// (`None`, wenn es noch keine gab). Reine Funktion, damit sich die Regeln
    /// ohne Browser prüfen lassen.
    ///
    /// Der Zeitabstand gilt NUR für das Intervall: beim Verlassen der Seite
    /// oder nach einer Nachricht soll sofort gesichert werden, sonst ginge
    /// genau der Anlass verloren. Die Rotations-Drossel gilt dagegen für alle
    /// Auslöser, weil sie den Wurzelschlüssel des Kontos schützt.
    pub fn action_for(
        &self,
        trigger: Trigger,
        now: u64,
        last_backup: Option<u64>,
        last_rotation: Option<u64>,
    ) -> Action {
        if !self.has(trigger) {
            return Action::Skip;
        }
        if trigger == Trigger::Interval {
            let due = match last_backup {
                Some(last) => now.saturating_sub(last) >= self.interval_secs,
                None => true,
            };
            if !due {
                return Action::Skip;
            }
        }
        if self.rotates_on(trigger) && self.rotation_allowed(now, last_rotation) {
            Action::BackupWithRotation
        } else {
            Action::Backup
        }
    }

    /// Ob die Drossel eine Rotation jetzt zulässt.
    fn rotation_allowed(&self, now: u64, last_rotation: Option<u64>) -> bool {
        match last_rotation {
            None => true,
            Some(last) => now.saturating_sub(last) >= self.rotation_min_gap_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(triggers: &[Trigger], rotate_on: &[Trigger]) -> AutoBackup {
        let mut cfg = AutoBackup {
            triggers: triggers.to_vec(),
            rotate_on: rotate_on.to_vec(),
            ..AutoBackup::default()
        };
        cfg.normalize();
        cfg
    }

    #[test]
    fn inactive_by_default() {
        let cfg = AutoBackup::default();
        assert!(!cfg.is_active());
        assert_eq!(
            cfg.action_for(Trigger::PageHide, 1000, None, None),
            Action::Skip
        );
    }

    #[test]
    fn unselected_trigger_does_nothing() {
        let cfg = with(&[Trigger::PageHide], &[]);
        assert_eq!(
            cfg.action_for(Trigger::MessageReceived, 1000, None, None),
            Action::Skip
        );
    }

    /// Das Intervall wartet den Abstand ab; die anderen Auslöser nicht, sonst
    /// ginge der Anlass (Verlassen, Nachricht) verloren.
    #[test]
    fn interval_waits_but_other_triggers_fire_at_once() {
        let cfg = with(&[Trigger::Interval, Trigger::PageHide], &[]);
        // Noch keine Sicherung: sofort fällig.
        assert_eq!(
            cfg.action_for(Trigger::Interval, 5_000, None, None),
            Action::Backup
        );
        // Vor Ablauf des Abstands: nichts.
        assert_eq!(
            cfg.action_for(Trigger::Interval, 5_000, Some(4_000), None),
            Action::Skip
        );
        // Genau am Abstand: fällig.
        assert_eq!(
            cfg.action_for(
                Trigger::Interval,
                4_000 + DEFAULT_INTERVAL_SECS,
                Some(4_000),
                None
            ),
            Action::Backup
        );
        // Verlassen sichert auch direkt nach einer Sicherung.
        assert_eq!(
            cfg.action_for(Trigger::PageHide, 4_001, Some(4_000), None),
            Action::Backup
        );
    }

    /// Der Kern der Kombinierbarkeit: mehrere Auslöser, Rotation nur bei einem
    /// davon (das Beispiel aus dem Auftrag).
    #[test]
    fn rotation_only_on_the_chosen_trigger() {
        let cfg = with(
            &[Trigger::Interval, Trigger::PageHide],
            &[Trigger::PageHide],
        );
        assert_eq!(
            cfg.action_for(Trigger::Interval, 100_000, None, None),
            Action::Backup
        );
        assert_eq!(
            cfg.action_for(Trigger::PageHide, 100_000, None, None),
            Action::BackupWithRotation
        );
    }

    /// Die Drossel verhindert Dauerrotation, sichert aber weiter.
    #[test]
    fn rotation_throttle_still_backs_up() {
        let cfg = with(&[Trigger::MessageReceived], &[Trigger::MessageReceived]);
        // Erste Rotation erlaubt.
        assert_eq!(
            cfg.action_for(Trigger::MessageReceived, 100_000, None, None),
            Action::BackupWithRotation
        );
        // Kurz danach: sichern ja, rotieren nein.
        assert_eq!(
            cfg.action_for(Trigger::MessageReceived, 100_060, None, Some(100_000)),
            Action::Backup
        );
        // Nach Ablauf der Drossel wieder mit Rotation.
        assert_eq!(
            cfg.action_for(
                Trigger::MessageReceived,
                100_000 + DEFAULT_ROTATION_MIN_GAP_SECS,
                None,
                Some(100_000)
            ),
            Action::BackupWithRotation
        );
    }

    /// Drossel 0 hebt die Begrenzung auf (ausdrückliche Wahl des Nutzers).
    #[test]
    fn zero_gap_rotates_every_time() {
        let mut cfg = with(&[Trigger::PageHide], &[Trigger::PageHide]);
        cfg.rotation_min_gap_secs = 0;
        assert_eq!(
            cfg.action_for(Trigger::PageHide, 100_001, None, Some(100_000)),
            Action::BackupWithRotation
        );
    }

    /// normalize räumt auf: ein Rotations-Haken ohne aktiven Auslöser hätte
    /// keine Wirkung und verschwindet, der Zeitabstand kommt auf die
    /// Untergrenze.
    #[test]
    fn normalize_drops_orphan_rotation_and_clamps_interval() {
        let mut cfg = AutoBackup {
            triggers: vec![Trigger::PageHide],
            rotate_on: vec![Trigger::Interval, Trigger::PageHide],
            interval_secs: 5,
            ..AutoBackup::default()
        };
        cfg.normalize();
        assert_eq!(cfg.rotate_on, vec![Trigger::PageHide]);
        assert_eq!(cfg.interval_secs, MIN_INTERVAL_SECS);
    }

    /// Alte Ablagen ohne die Felder bleiben lesbar (serde-Vorgaben).
    #[test]
    fn old_state_without_fields_is_readable() {
        let cfg: AutoBackup = serde_json::from_str("{}").unwrap();
        assert!(!cfg.is_active());
        assert_eq!(cfg.interval_secs, DEFAULT_INTERVAL_SECS);
        assert_eq!(cfg.rotation_min_gap_secs, DEFAULT_ROTATION_MIN_GAP_SECS);
    }
}
