//! Integrationstests des PgTenantStore gegen echtes PostgreSQL.
//!
//! Laufen nur mit TEST_DATABASE_URL_INTEGRATIONS (eigene Datenbank je
//! Dienst, sonst kollidieren die sqlx-Migrationstabellen), sonst still
//! übersprungen. Die Tests räumen nicht auf, sondern nutzen eindeutige
//! Namen pro Lauf.

use integrations::pg::{connect_and_migrate, PgTenantStore};
use integrations::store::{NewTenant, StoreError, TenantStore};
use uuid::Uuid;

async fn store() -> Option<PgTenantStore> {
    let url = std::env::var("TEST_DATABASE_URL_INTEGRATIONS").ok()?;
    let pool = connect_and_migrate(&url)
        .await
        .expect("Test-Datenbank erreichbar und migrierbar");
    Some(PgTenantStore::new(pool))
}

fn new_tenant(name: &str) -> NewTenant {
    NewTenant {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        client_id: name.to_string(),
        secret_hash: "phc-platzhalter".to_string(),
        scopes: vec!["notify".to_string(), "presence".to_string()],
        rate_limit: 60,
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn tenant_and_token_roundtrip() {
    let Some(store) = store().await else {
        return;
    };
    let name = format!("projekt-{}", Uuid::new_v4().simple());
    let tenant = new_tenant(&name);
    let tenant_id = tenant.id.clone();
    store.create(tenant).await.unwrap();

    // Anlage ist eindeutig je Name.
    let mut duplicate = new_tenant(&name);
    duplicate.id = Uuid::new_v4().to_string();
    assert!(matches!(
        store.create(duplicate).await,
        Err(StoreError::NameTaken)
    ));

    // Suche liefert Mandant samt Secret-Hash.
    let (found, secret_hash) = store.find_by_client_id(&name).await.unwrap().unwrap();
    assert_eq!(found.id, tenant_id);
    assert_eq!(found.name, name);
    assert_eq!(found.scopes, vec!["notify", "presence"]);
    assert_eq!(found.rate_limit, 60);
    assert!(!found.disabled);
    assert_eq!(secret_hash, "phc-platzhalter");
    assert!(store
        .find_by_client_id("gibt-es-nicht")
        .await
        .unwrap()
        .is_none());

    // Token-Umlauf: gültig auflösbar, abgelaufen nicht. Das Token trägt hier
    // bewusst nur 'notify' (Teilmenge der Mandanten-Rechte), damit die
    // Least-Privilege-Verengung auch über PostgreSQL geprüft ist.
    let valid_hash = format!("hash-{}", Uuid::new_v4().simple());
    let expired_hash = format!("hash-{}", Uuid::new_v4().simple());
    let token_scopes = vec!["notify".to_string()];
    store
        .save_token(&valid_hash, &tenant_id, &token_scopes, now_epoch() + 3600)
        .await
        .unwrap();
    store
        .save_token(&expired_hash, &tenant_id, &token_scopes, now_epoch() - 1)
        .await
        .unwrap();
    let resolved = store.find_token(&valid_hash).await.unwrap().unwrap();
    assert_eq!(resolved.id, tenant_id);
    // Nicht die vollen Mandanten-Scopes, sondern die des Tokens.
    assert_eq!(resolved.scopes, token_scopes);
    assert!(store.find_token(&expired_hash).await.unwrap().is_none());
    assert!(store.find_token("unbekannt").await.unwrap().is_none());

    // Der nächste Token-Tausch räumt abgelaufene Zeilen weg; der gültige
    // bleibt bestehen.
    let another_hash = format!("hash-{}", Uuid::new_v4().simple());
    store
        .save_token(&another_hash, &tenant_id, &token_scopes, now_epoch() + 3600)
        .await
        .unwrap();
    assert!(store.find_token(&valid_hash).await.unwrap().is_some());
}
