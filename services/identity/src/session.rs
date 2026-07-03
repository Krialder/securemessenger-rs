//! Session-Verwaltung: kurzlebige Access-Token und rotierende Refresh-Token (F020).
//!
//! Ein Login erzeugt eine Session-Familie: ein kurzlebiges Access-Token für
//! `Authorization: Bearer` und ein einmal verwendbares Refresh-Token. Jeder
//! Refresh rotiert beide. Legt jemand ein schon rotiertes Refresh-Token noch
//! einmal vor, lässt sich nicht unterscheiden, ob Angreifer oder legitimer
//! Client sendet; deshalb wird die ganze Familie widerrufen (Reuse Detection
//! nach OAuth 2.0 Security BCP, RFC 9700).
//!
//! Der Store sieht ausschließlich Token-Hashes (auth::token_hash). Klartext-
//! Tokens erreichen die Ablage nie, damit ein Auszug der Ablage (später:
//! DB-Leak, Backup) keine gültigen Sessions liefert.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

/// Token-Laufzeiten. Die Doku gibt keine Zahlen vor (schnittstellen.md sagt
/// nur "kurzlebig" und "rotiert"), deshalb Annahme: 15 Minuten Access,
/// 30 Tage Refresh. Aktive Nutzer bleiben durch die Rotation dauerhaft
/// angemeldet, nach 30 Tagen Inaktivität ist ein neuer Login fällig.
/// Die Annahme ist im Live-Dokument vermerkt.
#[derive(Clone, Copy, Debug)]
pub struct SessionConfig {
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            access_ttl: Duration::from_secs(15 * 60),
            refresh_ttl: Duration::from_secs(30 * 24 * 60 * 60),
        }
    }
}

/// Fehlschlag beim Refresh.
#[derive(Debug, PartialEq, Eq)]
pub enum RefreshError {
    /// Unbekanntes oder abgelaufenes Refresh-Token.
    Invalid,
    /// Ein bereits rotiertes Token wurde erneut vorgelegt; die Familie ist
    /// jetzt widerrufen. Nach außen wie Invalid beantworten (ein Angreifer
    /// soll nicht erfahren, dass er aufgeflogen ist), intern loggen.
    ReuseDetected,
    /// Ablage nicht erreichbar; wird 500, nie 401, sonst sähe ein
    /// DB-Ausfall wie eine widerrufene Session aus.
    Backend(String),
}

/// Wem eine Session gehört: Konto plus Gerät. Sessions sind gerätegebunden,
/// weil im Multi-Device-Modell jedes Gerät eigene Schlüssel hält und eigene
/// Nachrichten abholt; ein Widerruf des Geräts muss genau dessen Sessions
/// treffen (specs/geraete-identitaet.md).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionIdentity {
    pub handle: String,
    pub device_id: String,
}

/// Ablage für Session-Familien. Alle Methoden nehmen Token-Hashes entgegen,
/// nie Klartext. `refresh` ist in der PostgreSQL-Umsetzung eine einzige
/// Transaktion, sonst entsteht zwischen Prüfung und Rotation ein Fenster
/// für doppelte Rotation desselben Tokens.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Legt zu einem Login eine neue Familie mit frischem Token-Paar an.
    async fn create(
        &self,
        identity: SessionIdentity,
        access_hash: String,
        refresh_hash: String,
    ) -> Result<(), String>;

    /// Gibt die Identität zum Access-Hash, wenn die Session existiert und das
    /// Access-Token nicht abgelaufen ist. Tokens gelten bis ausschließlich
    /// ihres Ablaufzeitpunkts. Der äußere Fehler ist ein Backend-Ausfall
    /// (wird 500), das innere None ein unbekanntes Token (wird 401).
    async fn authenticate(&self, access_hash: &str) -> Result<Option<SessionIdentity>, String>;

    /// Rotiert die Familie: das alte Refresh-Token wird entwertet, das neue
    /// Paar gilt. Das alte Access-Token stirbt sofort mit, nicht erst bei
    /// Ablauf, damit ein gestohlenes Access-Token die nächste Rotation nicht
    /// überlebt. Gibt die Identität der Familie zurück.
    async fn refresh(
        &self,
        presented_refresh_hash: &str,
        new_access_hash: String,
        new_refresh_hash: String,
    ) -> Result<SessionIdentity, RefreshError>;

    /// Widerruft die Familie zum Access-Hash (Logout). Unbekannte Hashes sind
    /// kein Fehler, Logout ist idempotent.
    async fn revoke_by_access(&self, access_hash: &str) -> Result<(), String>;

    /// Widerruft alle Familien eines Geräts. Läuft beim Entfernen des Geräts
    /// (F040): ein revoziertes Gerät darf nicht weitersprechen.
    async fn revoke_device(&self, handle: &str, device_id: &str) -> Result<(), String>;
}

/// Eine Session-Familie: ein Gerät eines Nutzers, über Rotationen hinweg.
struct Family {
    identity: SessionIdentity,
    access_hash: String,
    access_expires_at: SystemTime,
    refresh_hash: String,
    refresh_expires_at: SystemTime,
    /// Bereits rotierte Refresh-Hashes, für die Reuse-Erkennung.
    used_refresh_hashes: HashSet<String>,
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    families: HashMap<u64, Family>,
    /// Aktueller Access-Hash zur Familie.
    by_access: HashMap<String, u64>,
    /// Refresh-Hash zur Familie: der aktuelle und die rotierten, denn auch
    /// ein altes Token muss zur Familie zurückführen, sonst gibt es keine
    /// Reuse-Erkennung.
    by_refresh: HashMap<String, u64>,
}

impl Inner {
    /// Entfernt eine Familie samt aller Index-Einträge, auch der rotierten
    /// Refresh-Hashes, damit kein Index auf eine gelöschte Familie zeigt.
    fn remove_family(&mut self, id: u64) {
        if let Some(family) = self.families.remove(&id) {
            self.by_access.remove(&family.access_hash);
            self.by_refresh.remove(&family.refresh_hash);
            for used in &family.used_refresh_hashes {
                self.by_refresh.remove(used);
            }
        }
    }

    /// Räumt Familien weg, deren Access- und Refresh-Token abgelaufen sind.
    /// Läuft bei jedem Login, damit die prozesslokale Ablage nicht unbegrenzt
    /// wächst. O(n) je Login ist hier vertretbar; produktiv übernimmt die
    /// Datenbank das Aufräumen.
    fn purge_expired(&mut self, now: SystemTime) {
        let dead: Vec<u64> = self
            .families
            .iter()
            .filter(|(_, f)| f.access_expires_at <= now && f.refresh_expires_at <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in dead {
            self.remove_family(id);
        }
    }
}

/// Prozesslokale Umsetzung hinter einem RwLock, für Entwicklung ohne
/// Infrastruktur und für Tests; die Handler kennen nur den Trait. Kein
/// .await, solange der Lock gehalten wird.
pub struct InMemorySessionStore {
    config: SessionConfig,
    inner: RwLock<Inner>,
}

impl InMemorySessionStore {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            inner: RwLock::new(Inner::default()),
        }
    }

    #[cfg(test)]
    fn family_count(&self) -> usize {
        self.inner
            .read()
            .expect("Session-Lock nicht vergiftet")
            .families
            .len()
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn create(
        &self,
        identity: SessionIdentity,
        access_hash: String,
        refresh_hash: String,
    ) -> Result<(), String> {
        let now = SystemTime::now();
        let mut inner = self.inner.write().expect("Session-Lock nicht vergiftet");
        inner.purge_expired(now);
        let id = inner.next_id;
        inner.next_id += 1;
        inner.by_access.insert(access_hash.clone(), id);
        inner.by_refresh.insert(refresh_hash.clone(), id);
        inner.families.insert(
            id,
            Family {
                identity,
                access_hash,
                access_expires_at: now + self.config.access_ttl,
                refresh_hash,
                refresh_expires_at: now + self.config.refresh_ttl,
                used_refresh_hashes: HashSet::new(),
            },
        );
        Ok(())
    }

    async fn authenticate(&self, access_hash: &str) -> Result<Option<SessionIdentity>, String> {
        let inner = self.inner.read().expect("Session-Lock nicht vergiftet");
        let Some(&id) = inner.by_access.get(access_hash) else {
            return Ok(None);
        };
        let Some(family) = inner.families.get(&id) else {
            return Ok(None);
        };
        if family.access_expires_at <= SystemTime::now() {
            return Ok(None);
        }
        Ok(Some(family.identity.clone()))
    }

    async fn refresh(
        &self,
        presented_refresh_hash: &str,
        new_access_hash: String,
        new_refresh_hash: String,
    ) -> Result<SessionIdentity, RefreshError> {
        let now = SystemTime::now();
        let mut inner = self.inner.write().expect("Session-Lock nicht vergiftet");
        let Some(&id) = inner.by_refresh.get(presented_refresh_hash) else {
            return Err(RefreshError::Invalid);
        };
        // Befunde erst erheben, dann handeln: remove_family braucht &mut,
        // solange die Familie geliehen ist, geht das nicht.
        let (is_reuse, is_expired) = {
            let family = inner.families.get(&id).ok_or(RefreshError::Invalid)?;
            (
                family.used_refresh_hashes.contains(presented_refresh_hash),
                family.refresh_expires_at <= now,
            )
        };
        if is_reuse {
            inner.remove_family(id);
            return Err(RefreshError::ReuseDetected);
        }
        if is_expired {
            inner.remove_family(id);
            return Err(RefreshError::Invalid);
        }
        let (old_access, identity) = {
            let family = inner
                .families
                .get_mut(&id)
                .expect("Familie existiert, gerade geprüft");
            let old_access = std::mem::replace(&mut family.access_hash, new_access_hash.clone());
            let old_refresh = std::mem::replace(&mut family.refresh_hash, new_refresh_hash.clone());
            family.used_refresh_hashes.insert(old_refresh);
            family.access_expires_at = now + self.config.access_ttl;
            family.refresh_expires_at = now + self.config.refresh_ttl;
            (old_access, family.identity.clone())
        };
        inner.by_access.remove(&old_access);
        inner.by_access.insert(new_access_hash, id);
        // Der alte by_refresh-Eintrag bleibt absichtlich stehen: er führt
        // ein wiederverwendetes Token zur Familie zurück (Reuse-Erkennung).
        inner.by_refresh.insert(new_refresh_hash, id);
        Ok(identity)
    }

    async fn revoke_by_access(&self, access_hash: &str) -> Result<(), String> {
        let mut inner = self.inner.write().expect("Session-Lock nicht vergiftet");
        if let Some(&id) = inner.by_access.get(access_hash) {
            inner.remove_family(id);
        }
        Ok(())
    }

    async fn revoke_device(&self, handle: &str, device_id: &str) -> Result<(), String> {
        let mut inner = self.inner.write().expect("Session-Lock nicht vergiftet");
        // Linearer Scan über die Familien: In-Memory vertretbar, produktiv
        // erledigt das ein indizierter DELETE in der Datenbank.
        let dead: Vec<u64> = inner
            .families
            .iter()
            .filter(|(_, f)| f.identity.handle == handle && f.identity.device_id == device_id)
            .map(|(id, _)| *id)
            .collect();
        for id in dead {
            inner.remove_family(id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(access_secs: u64, refresh_secs: u64) -> InMemorySessionStore {
        InMemorySessionStore::new(SessionConfig {
            access_ttl: Duration::from_secs(access_secs),
            refresh_ttl: Duration::from_secs(refresh_secs),
        })
    }

    fn identity(handle: &str, device: &str) -> SessionIdentity {
        SessionIdentity {
            handle: handle.into(),
            device_id: device.into(),
        }
    }

    #[tokio::test]
    async fn create_and_authenticate() {
        let s = store(60, 60);
        s.create(identity("alice", "d1"), "a1".into(), "r1".into())
            .await
            .unwrap();
        assert_eq!(
            s.authenticate("a1").await.unwrap(),
            Some(identity("alice", "d1"))
        );
        assert_eq!(s.authenticate("unbekannt").await.unwrap(), None);
    }

    #[tokio::test]
    async fn expired_access_is_rejected() {
        // TTL 0: Ablauf ist der Erzeugungszeitpunkt, gültig bis
        // ausschließlich Ablauf, also sofort ungültig, ohne zu schlafen.
        let s = store(0, 60);
        s.create(identity("alice", "d1"), "a1".into(), "r1".into())
            .await
            .unwrap();
        assert_eq!(s.authenticate("a1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn rotation_invalidates_old_pair() {
        let s = store(60, 60);
        s.create(identity("alice", "d1"), "a1".into(), "r1".into())
            .await
            .unwrap();
        let who = s.refresh("r1", "a2".into(), "r2".into()).await.unwrap();
        assert_eq!(who, identity("alice", "d1"));
        // Das alte Access-Token stirbt mit der Rotation, nicht erst bei Ablauf.
        assert_eq!(s.authenticate("a1").await.unwrap(), None);
        assert_eq!(
            s.authenticate("a2").await.unwrap(),
            Some(identity("alice", "d1"))
        );
    }

    #[tokio::test]
    async fn reuse_revokes_family() {
        let s = store(60, 60);
        s.create(identity("alice", "d1"), "a1".into(), "r1".into())
            .await
            .unwrap();
        s.refresh("r1", "a2".into(), "r2".into()).await.unwrap();
        // r1 wurde rotiert; sein erneutes Auftauchen ist ein Diebstahl-Indiz
        // und widerruft die ganze Familie, auch das aktuelle Paar.
        assert_eq!(
            s.refresh("r1", "a3".into(), "r3".into()).await,
            Err(RefreshError::ReuseDetected)
        );
        assert_eq!(s.authenticate("a2").await.unwrap(), None);
        assert_eq!(
            s.refresh("r2", "a4".into(), "r4".into()).await,
            Err(RefreshError::Invalid)
        );
    }

    #[tokio::test]
    async fn expired_refresh_is_invalid() {
        let s = store(60, 0);
        s.create(identity("alice", "d1"), "a1".into(), "r1".into())
            .await
            .unwrap();
        assert_eq!(
            s.refresh("r1", "a2".into(), "r2".into()).await,
            Err(RefreshError::Invalid)
        );
    }

    #[tokio::test]
    async fn revoke_by_access_kills_family() {
        let s = store(60, 60);
        s.create(identity("alice", "d1"), "a1".into(), "r1".into())
            .await
            .unwrap();
        s.revoke_by_access("a1").await.unwrap();
        assert_eq!(s.authenticate("a1").await.unwrap(), None);
        assert_eq!(
            s.refresh("r1", "a2".into(), "r2".into()).await,
            Err(RefreshError::Invalid)
        );
    }

    #[tokio::test]
    async fn revoke_device_kills_only_that_devices_sessions() {
        let s = store(60, 60);
        s.create(identity("alice", "d1"), "a1".into(), "r1".into())
            .await
            .unwrap();
        s.create(identity("alice", "d2"), "a2".into(), "r2".into())
            .await
            .unwrap();
        s.create(identity("bob", "d1"), "a3".into(), "r3".into())
            .await
            .unwrap();
        s.revoke_device("alice", "d1").await.unwrap();
        // Nur alice/d1 stirbt; alice/d2 und bob/d1 (gleiche Geräte-ID,
        // anderes Konto) bleiben unberührt.
        assert_eq!(s.authenticate("a1").await.unwrap(), None);
        assert_eq!(
            s.authenticate("a2").await.unwrap(),
            Some(identity("alice", "d2"))
        );
        assert_eq!(
            s.authenticate("a3").await.unwrap(),
            Some(identity("bob", "d1"))
        );
    }

    #[tokio::test]
    async fn purge_removes_dead_families() {
        let s = store(0, 0);
        s.create(identity("alice", "d1"), "a1".into(), "r1".into())
            .await
            .unwrap();
        // Der zweite Login stößt das Aufräumen an und entfernt die
        // vollständig abgelaufene Familie von alice.
        s.create(identity("bob", "d1"), "a2".into(), "r2".into())
            .await
            .unwrap();
        assert_eq!(s.family_count(), 1);
    }
}
