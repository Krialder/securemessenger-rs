//! OPRF-Kern für Contact Discovery (specs/contact-discovery.md).
//!
//! Eine Oblivious Pseudorandom Function: Der Client blendet den gesuchten
//! Handle, der Server wertet die OPRF mit seinem geheimen Schlüssel aus,
//! ohne den Klartext zu sehen, der Client entblendet das Ergebnis zu
//! `PRF_k(handle)`. Damit schlägt er das Konto nach, ohne dass der Server
//! lernt, welcher Handle gesucht wurde, und ohne die Nutzerliste
//! durchzählen zu können (jede Auswertung braucht eine Server-Runde, die
//! rate-limitiert ist).
//!
//! Kein Eigenbau: die Konstruktion kommt aus der voprf-Bibliothek
//! (RFC 9497, base mode, Ristretto255 mit SHA-512), exakt gepinnt wie die
//! übrige Krypto. Dieses Crate legt nur die Ciphersuite an einer Stelle
//! fest und reicht Bytes hinein und heraus, damit Client und Server
//! dieselbe Rechnung machen.

use voprf::{BlindedElement, EvaluationElement, OprfClient, OprfServer, Ristretto255};

/// Die Plattform-Ciphersuite: Ristretto255 mit SHA-512, die Standard-Suite
/// der voprf-Bibliothek (RFC 9497).
type Suite = Ristretto255;

/// Fehler des OPRF-Kerns; Details bleiben knapp, die genaue Ursache liegt
/// in der Bibliothek und gehört nicht in eine API-Antwort.
#[derive(Debug)]
pub struct OprfError(pub String);

impl std::fmt::Display for OprfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OPRF-Fehler: {}", self.0)
    }
}

impl std::error::Error for OprfError {}

fn err(e: impl std::fmt::Display) -> OprfError {
    OprfError(e.to_string())
}

/// Der geheime OPRF-Schlüssel des Servers (Seed, 32 Byte). Aus einem
/// Secret; ohne konfigurierten Schlüssel erzeugt der Dienst einen
/// flüchtigen und warnt (dann sind Discovery-Ergebnisse nach einem
/// Neustart nicht mehr stabil).
pub struct ServerKey {
    server: OprfServer<Suite>,
}

impl ServerKey {
    /// Baut den Server-Schlüssel aus einem Seed (deterministisch: derselbe
    /// Seed ergibt denselben Schlüssel, damit die vorberechnete
    /// Discovery-Tabelle über Neustarts stabil bleibt).
    pub fn from_seed(seed: &[u8]) -> Result<Self, OprfError> {
        // RFC-9497-Ableitung des Schlüssels aus dem Seed; info leer.
        let server =
            OprfServer::<Suite>::new_from_seed(seed, b"securemessenger-cds-v1").map_err(err)?;
        Ok(Self { server })
    }

    /// Wertet ein geblendetes Element aus (die Server-Runde der OPRF).
    /// Der Server lernt dabei nichts über den Klartext.
    pub fn evaluate(&self, blinded: &[u8]) -> Result<Vec<u8>, OprfError> {
        let element = BlindedElement::<Suite>::deserialize(blinded).map_err(err)?;
        let evaluation = self.server.blind_evaluate(&element);
        Ok(evaluation.serialize().to_vec())
    }

    /// Rechnet `PRF_k(input)` direkt (ohne Blendung), für den Aufbau der
    /// serverseitigen Discovery-Tabelle: der Server kennt seine eigenen
    /// Handles ohnehin und indiziert sie unter dem PRF-Wert.
    pub fn prf(&self, input: &[u8]) -> Result<Vec<u8>, OprfError> {
        let output = self.server.evaluate(input).map_err(err)?;
        Ok(output.to_vec())
    }
}

/// Die Client-Seite einer laufenden Discovery-Anfrage: hält das
/// Blend-Geheimnis, bis die Server-Antwort entblendet wird.
pub struct BlindedQuery {
    client: OprfClient<Suite>,
    /// Das geblendete Element, das an den Server geht (serialisiert).
    pub blinded: Vec<u8>,
}

/// Blendet einen Handle für die Server-Auswertung. Der zurückgegebene
/// `BlindedQuery.blinded` geht an den Server; `finalize` entblendet dessen
/// Antwort.
pub fn blind(handle: &str) -> Result<BlindedQuery, OprfError> {
    let mut rng = rand::rngs::OsRng;
    let result = OprfClient::<Suite>::blind(handle.as_bytes(), &mut rng).map_err(err)?;
    Ok(BlindedQuery {
        client: result.state,
        blinded: result.message.serialize().to_vec(),
    })
}

impl BlindedQuery {
    /// Entblendet die Server-Auswertung zu `PRF_k(handle)`. Dieser Wert
    /// ist stabil (derselbe Handle ergibt bei gleichem Server-Schlüssel
    /// denselben Wert) und dient als Index in der Discovery-Tabelle.
    pub fn finalize(self, handle: &str, evaluation: &[u8]) -> Result<Vec<u8>, OprfError> {
        let element = EvaluationElement::<Suite>::deserialize(evaluation).map_err(err)?;
        let output = self
            .client
            .finalize(handle.as_bytes(), &element)
            .map_err(err)?;
        Ok(output.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Die eigentliche Eigenschaft: das entblendete Client-Ergebnis ist
    /// gleich dem direkten Server-PRF über denselben Handle. Damit kann der
    /// Client unter genau diesem Wert nachschlagen, den der Server für sein
    /// Konto vorberechnet hat.
    #[test]
    fn blind_evaluate_finalize_matches_server_prf() {
        let server = ServerKey::from_seed(&[7u8; 32]).unwrap();

        let query = blind("alice").unwrap();
        let evaluation = server.evaluate(&query.blinded).unwrap();
        let client_output = query.finalize("alice", &evaluation).unwrap();

        let server_output = server.prf(b"alice").unwrap();
        assert_eq!(
            client_output, server_output,
            "entblendetes Ergebnis muss dem direkten Server-PRF gleichen"
        );
    }

    #[test]
    fn different_handles_yield_different_outputs() {
        let server = ServerKey::from_seed(&[7u8; 32]).unwrap();
        assert_ne!(
            server.prf(b"alice").unwrap(),
            server.prf(b"bob").unwrap(),
            "verschiedene Handles ergeben verschiedene PRF-Werte"
        );
    }

    #[test]
    fn same_seed_is_deterministic() {
        let a = ServerKey::from_seed(&[9u8; 32]).unwrap();
        let b = ServerKey::from_seed(&[9u8; 32]).unwrap();
        assert_eq!(
            a.prf(b"alice").unwrap(),
            b.prf(b"alice").unwrap(),
            "derselbe Seed ergibt stabile PRF-Werte (Tabelle überlebt Neustart)"
        );
    }
}
