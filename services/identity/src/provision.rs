//! Relay-Speicher für die QR-Kopplung (specs/geraete-identitaet.md).
//!
//! Das neue Gerät legt seinen unter einem Geheimnis verschlüsselten
//! Kopplungs-Antrag unter einer aus dem Geheimnis abgeleiteten Kanal-ID ab,
//! das freischaltende Gerät holt ihn dort ab. Der Relay ist bewusst dumm: er
//! transportiert opake Bytes und kennt weder das Geheimnis noch den Inhalt
//! (die Vertraulichkeit und die Integrität liegen im provisioning-Crate,
//! ChaCha20-Poly1305). Deshalb genügt eine flüchtige In-Memory-Ablage mit
//! kurzer Lebensdauer; ein Neustart verwirft offene Kanäle, dann zeigt das
//! neue Gerät einfach einen neuen QR-Code.
//!
//! [ANNAHME: In-Memory, prozesslokal. Ein Betrieb mit mehreren Replikas
//! bräuchte einen geteilten, ebenfalls kurzlebigen Speicher (etwa Redis mit
//! TTL); der Vertrag bleibt identisch, weil der Relay nie Klartext sieht.
//! Wie beim übrigen Betriebs-Ausbau als Grenze markiert, nicht als erledigt.]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Lebensdauer eines Kanals: lang genug, um in Ruhe zu scannen, kurz genug,
/// dass ein liegengebliebener Antrag rasch verfällt.
const TTL: Duration = Duration::from_secs(10 * 60);

/// Obergrenze des Base64-Chiffretexts. Der Antrag ist klein (Geräte-ID plus
/// öffentlicher Schlüssel); alles Größere ist Missbrauch.
pub const MAX_CIPHERTEXT_B64: usize = 4096;

/// Obergrenze des Base64-Nonce. Ein Nonce ist genau 12 Bytes (16 Base64-
/// Zeichen); großzügig gedeckelt, damit ein riesiges Nonce-Feld nicht am
/// Chiffretext-Deckel vorbei den Speicher füllt.
const MAX_NONCE_B64: usize = 64;

/// Deckel der gleichzeitig offenen Kanäle, damit der Speicher nicht
/// unbegrenzt wächst, falls jemand viele Kanäle anlegt und nie abholt.
const MAX_CHANNELS: usize = 100_000;

/// Länge der Kanal-ID als Hex-Zeichen (16 Bytes, siehe provisioning-Crate).
const CHANNEL_HEX_LEN: usize = 32;

struct Entry {
    nonce_b64: String,
    ciphertext_b64: String,
    expires_at: SystemTime,
}

/// Fehler beim Ablegen.
#[derive(Debug, PartialEq, Eq)]
pub enum PutError {
    /// Die Kanal-ID hat nicht das erwartete Format (32 Hex-Zeichen).
    InvalidChannel,
    /// Der Chiffretext ist zu groß.
    TooLarge,
    /// Der Kanal ist schon belegt. Erster gewinnt: ein zweiter Schreiber
    /// (etwa mit gestohlenem Geheimnis) kann den echten Antrag nicht still
    /// überschreiben, der Abruf liefert weiter den zuerst abgelegten. Im
    /// Normalfluss ist eine Kollision praktisch ausgeschlossen, weil das
    /// Geheimnis lokal frisch erzeugt und vor der Anzeige abgelegt wird; ein
    /// Angreifer kann den Kanal ohne Vorabkenntnis nicht treffen.
    ChannelTaken,
    /// Der Relay ist voll (Mengen-Deckel erreicht).
    Full,
}

/// Prozesslokaler, kurzlebiger Relay-Speicher.
#[derive(Default)]
pub struct ProvisionRelay {
    inner: Mutex<HashMap<String, Entry>>,
}

fn is_channel_id(channel: &str) -> bool {
    channel.len() == CHANNEL_HEX_LEN && channel.bytes().all(|b| b.is_ascii_hexdigit())
}

impl ProvisionRelay {
    /// Legt einen Kanal an. Räumt zunächst Abgelaufenes weg, prüft Format und
    /// Größe, und verweigert einen bereits belegten Kanal (erster gewinnt).
    pub fn put(
        &self,
        channel: &str,
        nonce_b64: String,
        ciphertext_b64: String,
    ) -> Result<(), PutError> {
        if !is_channel_id(channel) {
            return Err(PutError::InvalidChannel);
        }
        if ciphertext_b64.len() > MAX_CIPHERTEXT_B64 || nonce_b64.len() > MAX_NONCE_B64 {
            return Err(PutError::TooLarge);
        }
        let now = SystemTime::now();
        let mut map = self.inner.lock().expect("Relay-Lock nicht vergiftet");
        map.retain(|_, e| e.expires_at > now);
        if map.contains_key(channel) {
            return Err(PutError::ChannelTaken);
        }
        if map.len() >= MAX_CHANNELS {
            return Err(PutError::Full);
        }
        map.insert(
            channel.to_string(),
            Entry {
                nonce_b64,
                ciphertext_b64,
                expires_at: now + TTL,
            },
        );
        Ok(())
    }

    /// Holt einen Kanal EINMALIG und verbraucht ihn dabei (consume-on-read):
    /// das freischaltende Gerät holt den Antrag genau einmal, danach ist der
    /// Kanal weg. So ist ein einmal abgeholter Antrag nicht bis zum TTL
    /// erneut lesbar, und ein geleaktes Geheimnis nützt nach dem Abruf
    /// nichts mehr. `None` deckt alles ab (nie da, verfallen oder schon
    /// abgeholt): der Abrufer erfährt aus dem Relay nichts über den Grund.
    pub fn get(&self, channel: &str) -> Option<(String, String)> {
        let now = SystemTime::now();
        let mut map = self.inner.lock().expect("Relay-Lock nicht vergiftet");
        map.retain(|_, e| e.expires_at > now);
        map.remove(channel).map(|e| (e.nonce_b64, e.ciphertext_b64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get_roundtrip_consumes() {
        let relay = ProvisionRelay::default();
        let channel = "0".repeat(32);
        relay
            .put(&channel, "nonce".into(), "cipher".into())
            .unwrap();
        assert_eq!(relay.get(&channel), Some(("nonce".into(), "cipher".into())));
        // consume-on-read: ein zweiter Abruf findet nichts mehr.
        assert_eq!(relay.get(&channel), None);
        assert_eq!(relay.get(&"1".repeat(32)), None);
    }

    #[test]
    fn first_writer_wins() {
        let relay = ProvisionRelay::default();
        let channel = "a".repeat(32);
        relay.put(&channel, "n1".into(), "c1".into()).unwrap();
        assert_eq!(
            relay.put(&channel, "n2".into(), "c2".into()),
            Err(PutError::ChannelTaken)
        );
        // Der erste Inhalt bleibt.
        assert_eq!(relay.get(&channel), Some(("n1".into(), "c1".into())));
    }

    #[test]
    fn rejects_bad_channel_and_oversize() {
        let relay = ProvisionRelay::default();
        assert_eq!(
            relay.put("zu-kurz", "n".into(), "c".into()),
            Err(PutError::InvalidChannel)
        );
        assert_eq!(
            relay.put(&"g".repeat(32), "n".into(), "c".into()),
            Err(PutError::InvalidChannel)
        );
        let big = "A".repeat(MAX_CIPHERTEXT_B64 + 1);
        assert_eq!(
            relay.put(&"b".repeat(32), "n".into(), big),
            Err(PutError::TooLarge)
        );
        // Auch ein riesiges Nonce-Feld wird abgewiesen (nicht nur der
        // Chiffretext), sonst liefe der Groessendeckel am Nonce vorbei.
        let big_nonce = "A".repeat(MAX_NONCE_B64 + 1);
        assert_eq!(
            relay.put(&"c".repeat(32), big_nonce, "cipher".into()),
            Err(PutError::TooLarge)
        );
    }
}
