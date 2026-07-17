//! Gruppen-Zustellung (MLS Delivery Service, specs/mls-delivery-service.md).
//!
//! Der Server hält den kryptografischen Gruppenzustand nicht, den tragen
//! die Clients (TreeKEM). Er hält, was er fürs Zustellen und die Verwaltung
//! braucht: die Geräteliste (Fan-out), eine fortlaufende Epoche (Commit-
//! Serialisierung), den Gruppennamen (server-sichtbares Metadatum wie die
//! Mitgliedschaft), die Rollen je Handle (owner/admin/member) und die
//! Gruppen-Einstellungen. Die Auflösungsregel für konkurrierende Commits ist
//! first-wins nach Ankunft (409 mit aktueller Epoche für den Verlierer).
//!
//! ROLLEN sind SERVER-DURCHGESETZT, nicht Ende-zu-Ende verifizierbar: der
//! Server kontrolliert die Zustellung ohnehin und ist damit der natürliche
//! Durchsetzungspunkt (wie Matrix/Telegram), aber ein kompromittierter
//! Server könnte Rollen fälschen. Die kryptografische Verankerung der Rollen
//! (signierte Änderungs-Ereignisse) ist die dokumentierte Härtungsstufe.
//!
//! [ANNAHME: Die Bindung zwischen Geräteliste und kryptografischer
//! MLS-Mitgliedschaft prüft der Client (die Spec verlangt das). Der Server
//! nimmt die Mitglieder-Geräteliste vom committenden Client entgegen; er
//! verifiziert sie nicht kryptografisch. Die Rechte-Matrix (unten) ist die
//! Server-Durchsetzung.]

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Fehler der Gruppen-Ablage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupError {
    /// Technischer Fehler der Ablage; wird beim Aufrufer 500.
    Backend(String),
    /// Die Gruppe gibt es nicht.
    UnknownGroup,
    /// Eine Gruppe mit dieser ID existiert schon (Anlage).
    GroupExists,
    /// Der Commit zielte auf eine veraltete Epoche; die aktuelle ist
    /// beigelegt, damit der Client neu aufsetzen kann.
    StaleEpoch { current: u64 },
    /// Der Aufrufer ist kein Mitglied der Gruppe.
    NotMember,
    /// Der Aufrufer darf diese Aktion nicht (Rollen-/Einstellungs-Regel);
    /// der Grund ist für die Fehlermeldung gedacht.
    Forbidden(String),
}

impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupError::Backend(msg) => write!(f, "Backend-Fehler: {msg}"),
            GroupError::UnknownGroup => write!(f, "Gruppe unbekannt"),
            GroupError::GroupExists => write!(f, "Gruppe existiert bereits"),
            GroupError::StaleEpoch { current } => {
                write!(f, "Commit veraltet, aktuelle Epoche {current}")
            }
            GroupError::NotMember => write!(f, "kein Mitglied der Gruppe"),
            GroupError::Forbidden(reason) => write!(f, "nicht erlaubt: {reason}"),
        }
    }
}

/// Die drei Rollen. `owner` ist von Admins unantastbar und einmalig je
/// Gruppe; `admin` verwaltet nach unten (Mitglieder), nie seitwärts (andere
/// Admins); `member` kann nur selbst gehen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
}

impl Role {
    fn is_staff(self) -> bool {
        matches!(self, Role::Owner | Role::Admin)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Member => "member",
        }
    }
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "owner" => Some(Role::Owner),
            "admin" => Some(Role::Admin),
            "member" => Some(Role::Member),
            _ => None,
        }
    }
}

/// Wer darf eine geregelte Aktion (Einladen, Gruppeninfo ändern): alle
/// Mitglieder oder nur die Staff (Owner/Admin).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    All,
    Admins,
}

impl Policy {
    fn allows(self, role: Role) -> bool {
        match self {
            Policy::All => true,
            Policy::Admins => role.is_staff(),
        }
    }
}

/// Gruppen-Einstellungen (bewusst klein, Schnittmenge Signal/WhatsApp).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSettings {
    /// Wer darf Mitglieder hinzufügen (einladen).
    pub invite_policy: Policy,
    /// Announcement-Modus: nur Staff darf senden.
    pub announcement: bool,
    /// Wer darf Gruppeninfo/Einstellungen ändern.
    pub info_policy: Policy,
}

impl Default for GroupSettings {
    fn default() -> Self {
        // Einladen frei, senden frei, Gruppeninfo nur Staff.
        GroupSettings {
            invite_policy: Policy::All,
            announcement: false,
            info_policy: Policy::Admins,
        }
    }
}

/// Der Gruppenzustand, den der Server hält: Epoche und Mitglieds-Geräte fürs
/// Fan-out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupState {
    pub epoch: u64,
    pub devices: Vec<String>,
}

/// Verwaltungs-Sicht auf eine Gruppe: Name, Einstellungen, Rollen je Handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupMeta {
    pub name: String,
    pub settings: GroupSettings,
    /// Mitglieder-Handles mit Rolle, sortiert (Owner zuerst, dann Admins,
    /// dann Member, je alphabetisch) für stabile Anzeige.
    pub members: Vec<GroupMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupMember {
    pub handle: String,
    pub role: Role,
}

/// Die Angaben, die eine Gruppe bei der Anlage bekommt.
pub struct NewGroup<'a> {
    pub name: &'a str,
    /// Der Ersteller wird Owner.
    pub creator: &'a str,
    /// Alle Mitglieder-Handles (inklusive Ersteller); die anderen werden
    /// Member.
    pub member_handles: &'a [String],
    /// Die aufgelösten Geräte-IDs fürs Fan-out.
    pub devices: &'a [String],
}

/// Ein Commit mit Rollen-Kontext: der Aufrufer, die neue Mitglieder- und
/// Geräteliste. Die Store-Umsetzung setzt die Rechte-Matrix durch.
pub struct CommitContext<'a> {
    pub actor: &'a str,
    pub expected_epoch: u64,
    pub new_member_handles: &'a [String],
    pub new_devices: &'a [String],
}

#[async_trait]
pub trait GroupStore: Send + Sync {
    /// Legt eine Gruppe an (Epoche 0, Ersteller = Owner). `GroupExists`,
    /// wenn die client-erzeugte ID schon vergeben ist.
    async fn create_group(&self, group_id: &str, new: NewGroup<'_>) -> Result<(), GroupError>;

    /// Aktueller Zustell-Zustand (Epoche und Geräteliste) oder `UnknownGroup`.
    async fn state(&self, group_id: &str) -> Result<GroupState, GroupError>;

    /// Verwaltungs-Sicht (Name, Einstellungen, Rollen). Nur Mitglieder
    /// dürfen sie lesen (`NotMember` sonst).
    async fn meta(&self, group_id: &str, reader: &str) -> Result<GroupMeta, GroupError>;

    /// Serialisiert einen Commit und setzt dabei die Rechte-Matrix durch
    /// (wer darf wen hinzufügen/entfernen). Passt die Epoche, wird sie
    /// erhöht, die Geräteliste ersetzt, die Rollen der hinzugekommenen/
    /// entfernten Handles angepasst; sonst `StaleEpoch`/`Forbidden`. Liefert
    /// die neue Epoche.
    async fn commit(&self, group_id: &str, ctx: CommitContext<'_>) -> Result<u64, GroupError>;

    /// Ändert die Rolle eines Mitglieds (befördern/degradieren). Owner kann
    /// alles; ein Admin kann Member zu Admin machen nur, wenn er selbst Owner
    /// ist (Standard: nur Owner befördert). Owner-Rolle vergibt nur der
    /// Transfer. Liefert die aktualisierte Verwaltungs-Sicht.
    async fn set_role(
        &self,
        group_id: &str,
        actor: &str,
        target: &str,
        role: Role,
    ) -> Result<GroupMeta, GroupError>;

    /// Übergibt die Owner-Rolle an ein bestehendes Mitglied; der bisherige
    /// Owner wird Admin. Nur der Owner darf das.
    async fn transfer_ownership(
        &self,
        group_id: &str,
        actor: &str,
        target: &str,
    ) -> Result<GroupMeta, GroupError>;

    /// Ändert Name und/oder Einstellungen. Erlaubt nach `info_policy`
    /// (Standard nur Staff).
    async fn update_info(
        &self,
        group_id: &str,
        actor: &str,
        name: Option<&str>,
        settings: Option<GroupSettings>,
    ) -> Result<GroupMeta, GroupError>;
}

/// Der interne Vollzustand einer Gruppe. `pub(crate)`, damit die
/// PostgreSQL-Umsetzung die geladene Zeile in denselben Regel-Funktionen
/// verarbeitet (eine Quelle der Wahrheit für die Rechte-Matrix).
#[derive(Clone)]
pub(crate) struct GroupRecord {
    pub(crate) epoch: u64,
    pub(crate) devices: Vec<String>,
    pub(crate) name: String,
    pub(crate) settings: GroupSettings,
    /// Handle -> Rolle.
    pub(crate) roles: HashMap<String, Role>,
}

impl GroupRecord {
    pub(crate) fn require_member(&self, handle: &str) -> Result<Role, GroupError> {
        self.roles.get(handle).copied().ok_or(GroupError::NotMember)
    }

    pub(crate) fn meta(&self) -> GroupMeta {
        let mut members: Vec<GroupMember> = self
            .roles
            .iter()
            .map(|(handle, role)| GroupMember {
                handle: handle.clone(),
                role: *role,
            })
            .collect();
        // Owner < Admin < Member, dann alphabetisch: stabile Anzeige.
        members.sort_by(|a, b| {
            fn rank(r: Role) -> u8 {
                match r {
                    Role::Owner => 0,
                    Role::Admin => 1,
                    Role::Member => 2,
                }
            }
            rank(a.role)
                .cmp(&rank(b.role))
                .then_with(|| a.handle.cmp(&b.handle))
        });
        GroupMeta {
            name: self.name.clone(),
            settings: self.settings.clone(),
            members,
        }
    }
}

/// Setzt die Commit-Rechte durch und liefert die Rollen-Änderungen (added als
/// Member, removed als Weg). Reine Funktion, damit In-Memory und PG dieselbe
/// Regel nutzen.
pub(crate) fn authorize_commit(
    record: &GroupRecord,
    actor: &str,
    new_handles: &HashSet<String>,
) -> Result<(), GroupError> {
    let actor_role = record.require_member(actor)?;
    let old: HashSet<&String> = record.roles.keys().collect();
    let removed: Vec<&String> = old
        .iter()
        .filter(|h| !new_handles.contains(**h))
        .copied()
        .collect();
    let added: Vec<&String> = new_handles.iter().filter(|h| !old.contains(*h)).collect();

    // Reines Selbst-Verlassen (nur der Aufrufer fällt weg, sonst nichts):
    // jedes Mitglied darf gehen; nur der Owner muss vorher übergeben, solange
    // andere übrig bleiben.
    let only_self_leaves = removed.len() == 1 && removed[0] == actor && added.is_empty();
    if only_self_leaves {
        if actor_role == Role::Owner && new_handles.iter().any(|h| h != actor) {
            return Err(GroupError::Forbidden(
                "Der Owner muss die Rolle erst übergeben, bevor er die Gruppe verlässt".into(),
            ));
        }
        return Ok(());
    }

    // Entfernen anderer (Moderation): nur Staff, nie den Owner, und ein Admin
    // nicht seitwärts (keine anderen Admins).
    for target in &removed {
        if target.as_str() == actor {
            continue; // sich selbst mit-entfernen ist beim Umbau erlaubt
        }
        if !actor_role.is_staff() {
            return Err(GroupError::Forbidden(
                "Nur Admins dürfen Mitglieder entfernen".into(),
            ));
        }
        match record.roles.get(*target) {
            Some(Role::Owner) => {
                return Err(GroupError::Forbidden(
                    "Der Owner ist nicht entfernbar".into(),
                ))
            }
            Some(Role::Admin) if actor_role != Role::Owner => {
                return Err(GroupError::Forbidden(
                    "Nur der Owner darf Admins entfernen".into(),
                ))
            }
            _ => {}
        }
    }

    // Hinzufügen (Einladen): nach invite_policy.
    if !added.is_empty() && !record.settings.invite_policy.allows(actor_role) {
        return Err(GroupError::Forbidden(
            "In dieser Gruppe dürfen nur Admins einladen".into(),
        ));
    }
    Ok(())
}

pub(crate) fn dedup(devices: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    devices
        .iter()
        .filter(|d| seen.insert((*d).clone()))
        .cloned()
        .collect()
}

#[derive(Default)]
struct Inner {
    groups: HashMap<String, GroupRecord>,
}

/// Prozesslokale Gruppen-Ablage (Tests, Entwicklung). Gleiche Semantik wie
/// die PG-Umsetzung; die Serialisierung liegt hier im Mutex, dort in einer
/// Transaktion mit Zeilensperre.
#[derive(Default)]
pub struct InMemoryGroupStore {
    inner: Mutex<Inner>,
}

#[async_trait]
impl GroupStore for InMemoryGroupStore {
    async fn create_group(&self, group_id: &str, new: NewGroup<'_>) -> Result<(), GroupError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        if inner.groups.contains_key(group_id) {
            return Err(GroupError::GroupExists);
        }
        let mut roles = HashMap::new();
        for handle in new.member_handles {
            roles.insert(handle.clone(), Role::Member);
        }
        roles.insert(new.creator.to_string(), Role::Owner);
        inner.groups.insert(
            group_id.to_string(),
            GroupRecord {
                epoch: 0,
                devices: dedup(new.devices),
                name: new.name.to_string(),
                settings: GroupSettings::default(),
                roles,
            },
        );
        Ok(())
    }

    async fn state(&self, group_id: &str) -> Result<GroupState, GroupError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        inner
            .groups
            .get(group_id)
            .map(|r| GroupState {
                epoch: r.epoch,
                devices: r.devices.clone(),
            })
            .ok_or(GroupError::UnknownGroup)
    }

    async fn meta(&self, group_id: &str, reader: &str) -> Result<GroupMeta, GroupError> {
        let inner = self.inner.lock().expect("Lock nicht vergiftet");
        let record = inner.groups.get(group_id).ok_or(GroupError::UnknownGroup)?;
        record.require_member(reader)?;
        Ok(record.meta())
    }

    async fn commit(&self, group_id: &str, ctx: CommitContext<'_>) -> Result<u64, GroupError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        let record = inner
            .groups
            .get_mut(group_id)
            .ok_or(GroupError::UnknownGroup)?;
        if record.epoch != ctx.expected_epoch {
            return Err(GroupError::StaleEpoch {
                current: record.epoch,
            });
        }
        let new_handles: HashSet<String> = ctx.new_member_handles.iter().cloned().collect();
        authorize_commit(record, ctx.actor, &new_handles)?;
        // Rollen anpassen: neue werden Member, weggefallene raus. Bestehende
        // behalten ihre Rolle.
        record.roles.retain(|h, _| new_handles.contains(h));
        for handle in &new_handles {
            record.roles.entry(handle.clone()).or_insert(Role::Member);
        }
        record.epoch += 1;
        record.devices = dedup(ctx.new_devices);
        Ok(record.epoch)
    }

    async fn set_role(
        &self,
        group_id: &str,
        actor: &str,
        target: &str,
        role: Role,
    ) -> Result<GroupMeta, GroupError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        let record = inner
            .groups
            .get_mut(group_id)
            .ok_or(GroupError::UnknownGroup)?;
        apply_set_role(record, actor, target, role)?;
        Ok(record.meta())
    }

    async fn transfer_ownership(
        &self,
        group_id: &str,
        actor: &str,
        target: &str,
    ) -> Result<GroupMeta, GroupError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        let record = inner
            .groups
            .get_mut(group_id)
            .ok_or(GroupError::UnknownGroup)?;
        apply_transfer(record, actor, target)?;
        Ok(record.meta())
    }

    async fn update_info(
        &self,
        group_id: &str,
        actor: &str,
        name: Option<&str>,
        settings: Option<GroupSettings>,
    ) -> Result<GroupMeta, GroupError> {
        let mut inner = self.inner.lock().expect("Lock nicht vergiftet");
        let record = inner
            .groups
            .get_mut(group_id)
            .ok_or(GroupError::UnknownGroup)?;
        apply_update_info(record, actor, name, settings)?;
        Ok(record.meta())
    }
}

// Die Regel-Anwendungen als freie Funktionen, damit die PG-Umsetzung nach
// dem Laden der Zeile exakt dieselbe Logik fahren kann.

pub(crate) fn apply_set_role(
    record: &mut GroupRecord,
    actor: &str,
    target: &str,
    role: Role,
) -> Result<(), GroupError> {
    let actor_role = record.require_member(actor)?;
    let target_role = record.require_member(target)?;
    if role == Role::Owner {
        return Err(GroupError::Forbidden(
            "Die Owner-Rolle wird nur über die Übergabe vergeben".into(),
        ));
    }
    if target_role == Role::Owner {
        return Err(GroupError::Forbidden(
            "Der Owner ist nicht degradierbar (erst übergeben)".into(),
        ));
    }
    // Befördern zu Admin: nur der Owner. Degradieren zu Member: Owner immer;
    // ein Admin darf nur Member betreffen, nie andere Admins (nicht seitwärts).
    match role {
        Role::Admin => {
            if actor_role != Role::Owner {
                return Err(GroupError::Forbidden(
                    "Nur der Owner befördert zu Admin".into(),
                ));
            }
        }
        Role::Member => {
            if !actor_role.is_staff() {
                return Err(GroupError::Forbidden("Nur Admins ändern Rollen".into()));
            }
            if target_role == Role::Admin && actor_role != Role::Owner {
                return Err(GroupError::Forbidden(
                    "Nur der Owner degradiert Admins".into(),
                ));
            }
        }
        Role::Owner => unreachable!(),
    }
    record.roles.insert(target.to_string(), role);
    Ok(())
}

pub(crate) fn apply_transfer(
    record: &mut GroupRecord,
    actor: &str,
    target: &str,
) -> Result<(), GroupError> {
    let actor_role = record.require_member(actor)?;
    record.require_member(target)?;
    if actor_role != Role::Owner {
        return Err(GroupError::Forbidden("Nur der Owner überträgt".into()));
    }
    if target == actor {
        return Ok(());
    }
    record.roles.insert(actor.to_string(), Role::Admin);
    record.roles.insert(target.to_string(), Role::Owner);
    Ok(())
}

pub(crate) fn apply_update_info(
    record: &mut GroupRecord,
    actor: &str,
    name: Option<&str>,
    settings: Option<GroupSettings>,
) -> Result<(), GroupError> {
    let actor_role = record.require_member(actor)?;
    if !record.settings.info_policy.allows(actor_role) {
        return Err(GroupError::Forbidden(
            "Gruppeninfo darf hier nur Staff ändern".into(),
        ));
    }
    if let Some(name) = name {
        record.name = name.to_string();
    }
    if let Some(settings) = settings {
        record.settings = settings;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn devs(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    async fn group_with(store: &InMemoryGroupStore, members: &[&str]) {
        let handles = devs(members);
        store
            .create_group(
                "g1",
                NewGroup {
                    name: "Team",
                    creator: members[0],
                    member_handles: &handles,
                    devices: &devs(&["dev-a"]),
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn creator_is_owner_rest_member() {
        let store = InMemoryGroupStore::default();
        group_with(&store, &["alice", "bob", "carl"]).await;
        let meta = store.meta("g1", "alice").await.unwrap();
        assert_eq!(meta.name, "Team");
        assert_eq!(meta.members[0].handle, "alice");
        assert_eq!(meta.members[0].role, Role::Owner);
        assert!(meta.members[1..].iter().all(|m| m.role == Role::Member));
        // Ein Nicht-Mitglied darf die Verwaltungssicht nicht lesen.
        assert_eq!(
            store.meta("g1", "mallory").await,
            Err(GroupError::NotMember)
        );
    }

    #[tokio::test]
    async fn owner_promotes_admin_and_admin_cannot() {
        let store = InMemoryGroupStore::default();
        group_with(&store, &["alice", "bob", "carl"]).await;
        // Owner befördert bob zu Admin.
        store
            .set_role("g1", "alice", "bob", Role::Admin)
            .await
            .unwrap();
        // Admin bob darf carl NICHT befördern (nur der Owner).
        assert!(matches!(
            store.set_role("g1", "bob", "carl", Role::Admin).await,
            Err(GroupError::Forbidden(_))
        ));
        // Admin darf den Owner nicht degradieren.
        assert!(matches!(
            store.set_role("g1", "bob", "alice", Role::Member).await,
            Err(GroupError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn admin_removes_member_but_not_owner_or_admin() {
        let store = InMemoryGroupStore::default();
        group_with(&store, &["alice", "bob", "carl", "dora"]).await;
        store
            .set_role("g1", "alice", "bob", Role::Admin)
            .await
            .unwrap();
        // Admin bob entfernt Member carl (Commit ohne carl).
        let epoch = store
            .commit(
                "g1",
                CommitContext {
                    actor: "bob",
                    expected_epoch: 0,
                    new_member_handles: &devs(&["alice", "bob", "dora"]),
                    new_devices: &devs(&["dev-a"]),
                },
            )
            .await
            .unwrap();
        assert_eq!(epoch, 1);
        // Admin bob darf den Owner nicht entfernen.
        assert!(matches!(
            store
                .commit(
                    "g1",
                    CommitContext {
                        actor: "bob",
                        expected_epoch: 1,
                        new_member_handles: &devs(&["bob", "dora"]),
                        new_devices: &devs(&["dev-a"]),
                    },
                )
                .await,
            Err(GroupError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn member_can_only_leave_self() {
        let store = InMemoryGroupStore::default();
        group_with(&store, &["alice", "bob", "carl"]).await;
        // Member carl entfernt bob: verboten.
        assert!(matches!(
            store
                .commit(
                    "g1",
                    CommitContext {
                        actor: "carl",
                        expected_epoch: 0,
                        new_member_handles: &devs(&["alice", "carl"]),
                        new_devices: &devs(&["dev-a"]),
                    },
                )
                .await,
            Err(GroupError::Forbidden(_))
        ));
        // Member carl verlässt sich selbst: erlaubt.
        store
            .commit(
                "g1",
                CommitContext {
                    actor: "carl",
                    expected_epoch: 0,
                    new_member_handles: &devs(&["alice", "bob"]),
                    new_devices: &devs(&["dev-a"]),
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn owner_must_transfer_before_leaving() {
        let store = InMemoryGroupStore::default();
        group_with(&store, &["alice", "bob"]).await;
        // Owner alice will gehen, solange bob bleibt: verboten.
        assert!(matches!(
            store
                .commit(
                    "g1",
                    CommitContext {
                        actor: "alice",
                        expected_epoch: 0,
                        new_member_handles: &devs(&["bob"]),
                        new_devices: &devs(&["dev-a"]),
                    },
                )
                .await,
            Err(GroupError::Forbidden(_))
        ));
        // Nach der Übergabe ist bob Owner, alice Admin und darf gehen.
        store
            .transfer_ownership("g1", "alice", "bob")
            .await
            .unwrap();
        store
            .commit(
                "g1",
                CommitContext {
                    actor: "alice",
                    expected_epoch: 0,
                    new_member_handles: &devs(&["bob"]),
                    new_devices: &devs(&["dev-a"]),
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn invite_policy_admins_blocks_member_add() {
        let store = InMemoryGroupStore::default();
        group_with(&store, &["alice", "bob"]).await;
        // Owner stellt "nur Admins einladen".
        store
            .update_info(
                "g1",
                "alice",
                None,
                Some(GroupSettings {
                    invite_policy: Policy::Admins,
                    announcement: false,
                    info_policy: Policy::Admins,
                }),
            )
            .await
            .unwrap();
        // Member bob will carl hinzufügen: verboten.
        assert!(matches!(
            store
                .commit(
                    "g1",
                    CommitContext {
                        actor: "bob",
                        expected_epoch: 0,
                        new_member_handles: &devs(&["alice", "bob", "carl"]),
                        new_devices: &devs(&["dev-a"]),
                    },
                )
                .await,
            Err(GroupError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn stale_and_unknown_still_reported() {
        let store = InMemoryGroupStore::default();
        group_with(&store, &["alice", "bob"]).await;
        store
            .commit(
                "g1",
                CommitContext {
                    actor: "alice",
                    expected_epoch: 0,
                    new_member_handles: &devs(&["alice", "bob", "carl"]),
                    new_devices: &devs(&["dev-a"]),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .commit(
                    "g1",
                    CommitContext {
                        actor: "alice",
                        expected_epoch: 0,
                        new_member_handles: &devs(&["alice", "bob"]),
                        new_devices: &devs(&["dev-a"]),
                    },
                )
                .await,
            Err(GroupError::StaleEpoch { current: 1 })
        );
        assert_eq!(store.state("nope").await, Err(GroupError::UnknownGroup));
    }
}
