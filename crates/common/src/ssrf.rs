//! SSRF-Schutz für ausgehende Aufrufe an vom Nutzer bestimmte URLs.
//!
//! Mehrere Dienste rufen URLs auf, die ein Client vorgibt: integrations die
//! Webhook-Ziele, delivery die Web-Push-Endpoints. Beide dürfen NICHT auf
//! interne Ziele zeigen (Loopback, private Bereiche, Cloud-Metadaten), sonst
//! wird der Dienst zum SSRF-Sprungbrett ins interne Netz. Diese Prüfung liegt
//! an einer Stelle, damit die Regel nicht zwischen den Diensten auseinander-
//! läuft.
//!
//! WICHTIG: Der Host wird mit DEMSELBEN Parser gezogen, den reqwest zum
//! Verbinden nutzt (das `url`-Crate, WHATWG-konform). Ein selbstgebauter
//! Zerleger wäre gefährlich, weil er sich vom tatsächlich angesprochenen Host
//! unterscheiden kann: das url-Crate normalisiert dezimale/hexadezimale/
//! oktale IPv4-Literale (`https://2130706433/` -> 127.0.0.1) und behandelt bei
//! http(s) den Backslash wie einen Schrägstrich (`https://127.0.0.1\@ok/` ->
//! Host 127.0.0.1). Ein String-Parser, der das anders sieht, prüft den
//! falschen Host und lässt genau diese internen Ziele durch.
//!
//! Die Prüfung greift auf der Anwendungsschicht (literale interne Ziele). Ein
//! DNS-Name, der erst zur Verbindungszeit intern auflöst (DNS-Rebinding),
//! fällt hier durch; dagegen schützt zusätzlich die Egress-Policy des Netzes
//! (deploy/k8s).

use std::net::IpAddr;

use url::{Host, Url};

/// Zeigt die URL auf ein internes/gefährliches Ziel? Loopback,
/// private/Link-lokale/ULA-Bereiche, Multicast, unspezifiziert, `localhost`,
/// `.internal`/`metadata` (Cloud-Metadaten). Eine URL, die sich nicht als
/// absolute URL mit Host parsen lässt, gilt als blockiert (lieber ablehnen
/// als raten).
pub fn is_blocked_host(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return true;
    };
    // Nur http(s) darf durch: das url-Crate normalisiert IP-Literale nur bei
    // diesen „special schemes"; bei einem anderen Schema bliebe ein IP-Host
    // ein undurchsuchter Domain-String und rutschte durch. Die Aufrufer
    // prüfen das Schema ohnehin, aber dieser geteilte Filter soll für sich
    // stehen (ein künftiger Aufrufer verlässt sich vielleicht allein darauf).
    if !matches!(parsed.scheme(), "http" | "https") {
        return true;
    }
    match parsed.host() {
        // Das url-Crate liefert IP-Literale bereits normalisiert (dezimal/hex/
        // oktal/gemischt -> die echte Adresse), also gegen den TATSÄCHLICHEN
        // Verbindungshost geprüft.
        Some(Host::Ipv4(v4)) => is_internal_ip(IpAddr::V4(v4)),
        Some(Host::Ipv6(v6)) => is_internal_ip(IpAddr::V6(v6)),
        Some(Host::Domain(domain)) => {
            let lower = domain.to_ascii_lowercase();
            lower == "localhost"
                || lower.ends_with(".localhost")
                || lower == "metadata"
                || lower.ends_with(".internal")
        }
        None => true, // ohne Host (z. B. mailto:, data:) nichts zum Anrufen
    }
}

/// Ob eine IP in einem internen/nicht-öffentlichen Bereich liegt.
pub fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.octets()[0] == 0 // 0.0.0.0/8
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                // Eine IPv6-Adresse, die eine IPv4 einbettet (v4-mapped,
                // NAT64, 6to4, v4-compatible), gilt intern, wenn die
                // eingebettete IPv4 intern ist: hinter einem NAT64/6to4-Gateway
                // landet der Aufruf sonst doch beim internen IPv4-Ziel.
                || embedded_ipv4(v6).is_some_and(|m| is_internal_ip(IpAddr::V4(m)))
        }
    }
}

/// Zieht eine in eine IPv6-Adresse eingebettete IPv4 heraus, wo definiert:
/// v4-mapped (`::ffff:a.b.c.d`), NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`)
/// und die veraltete v4-compatible-Form (`::a.b.c.d`, `::/96`).
fn embedded_ipv4(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let s = v6.segments();
    // v4-mapped ::ffff:0:0/96
    if let Some(m) = v6.to_ipv4_mapped() {
        return Some(m);
    }
    // NAT64 well-known 64:ff9b::/96 (letzte 32 Bit = IPv4).
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(std::net::Ipv4Addr::from(
            ((s[6] as u32) << 16) | s[7] as u32,
        ));
    }
    // 6to4 2002::/16 (Bits 16..48 = IPv4).
    if s[0] == 0x2002 {
        return Some(std::net::Ipv4Addr::from(
            ((s[1] as u32) << 16) | s[2] as u32,
        ));
    }
    // v4-compatible ::/96 (veraltet): erste 96 Bit null, letzte 32 = IPv4.
    // :: und ::1 sind schon anderweitig abgefangen; hier zaehlt die IPv4.
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(std::net::Ipv4Addr::from(
            ((s[6] as u32) << 16) | s[7] as u32,
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_hosts_pass() {
        assert!(!is_blocked_host("https://fcm.googleapis.com/fcm/send/x"));
        assert!(!is_blocked_host(
            "https://updates.push.services.mozilla.com/wpush/v2/y"
        ));
        assert!(!is_blocked_host("https://8.8.8.8/x"));
    }

    #[test]
    fn internal_targets_are_blocked() {
        assert!(is_blocked_host("http://localhost/x"));
        assert!(is_blocked_host("https://app.localhost/x"));
        assert!(is_blocked_host("https://127.0.0.1/x"));
        assert!(is_blocked_host("https://10.0.0.5/x"));
        assert!(is_blocked_host("https://192.168.1.1/x"));
        assert!(is_blocked_host("https://169.254.169.254/latest/meta-data"));
        assert!(is_blocked_host("https://metadata/x"));
        assert!(is_blocked_host("https://foo.internal/x"));
        assert!(is_blocked_host("https://[::1]/x"));
        assert!(is_blocked_host("https://[fd00::1]/x"));
        assert!(is_blocked_host("nonsense"));
        // Userinfo darf den Host nicht verschleiern.
        assert!(is_blocked_host("https://fcm.googleapis.com@127.0.0.1/x"));
    }

    /// Die Parser-Umgehungen aus dem Review: nicht-kanonische IP-Literale und
    /// der Backslash-Trick. Der WHATWG-Parser (url-Crate) normalisiert sie
    /// zum echten internen Host, den der Filter jetzt sieht.
    #[test]
    fn non_canonical_bypasses_are_blocked() {
        // Dezimal/hex/oktal -> 127.0.0.1 bzw. 169.254.169.254.
        assert!(is_blocked_host("https://2130706433/x")); // 127.0.0.1
        assert!(is_blocked_host("https://0x7f000001/x")); // 127.0.0.1
        assert!(is_blocked_host("https://2852039166/latest/meta-data/")); // 169.254.169.254
        assert!(is_blocked_host("https://0251.0376.0251.0376/x")); // 169.254.169.254
                                                                   // Trailing dot.
        assert!(is_blocked_host("https://127.0.0.1./x"));
        // Backslash-Autoritaet (special-scheme): der echte Host ist 127.0.0.1.
        assert!(is_blocked_host("https://127.0.0.1\\@fcm.googleapis.com/x"));
    }

    /// IPv6-Adressen, die eine interne IPv4 einbetten (NAT64/6to4/
    /// v4-compatible), muessen blockiert sein: hinter einem NAT64/6to4-Gateway
    /// landet der Aufruf sonst doch am internen IPv4-Ziel.
    #[test]
    fn ipv6_embedded_internal_ipv4_is_blocked() {
        // NAT64 64:ff9b::/96 mit 169.254.169.254 (Cloud-Metadaten).
        assert!(is_blocked_host(
            "https://[64:ff9b::a9fe:a9fe]/latest/meta-data"
        ));
        // NAT64 mit 127.0.0.1.
        assert!(is_blocked_host("https://[64:ff9b::7f00:1]/x"));
        // 6to4 2002::/16 mit 127.0.0.1.
        assert!(is_blocked_host("https://[2002:7f00:1::]/x"));
        // v4-compatible ::/96 mit 127.0.0.1.
        assert!(is_blocked_host("https://[::127.0.0.1]/x"));
        // v4-mapped ::ffff:169.254.169.254.
        assert!(is_blocked_host("https://[::ffff:169.254.169.254]/x"));
        // Eine NAT64-Einbettung einer OEFFENTLICHEN IPv4 bleibt erlaubt.
        assert!(!is_blocked_host("https://[64:ff9b::808:808]/x")); // 8.8.8.8
    }

    /// Nicht-http(s)-Schemata sind blockiert: das url-Crate normalisiert
    /// IP-Literale nur bei special schemes, ein anderer Schema-Host bliebe
    /// undurchsucht.
    #[test]
    fn non_http_schemes_are_blocked() {
        assert!(is_blocked_host("ftp://127.0.0.1/x"));
        assert!(is_blocked_host("foo://127.0.0.1/x"));
        assert!(is_blocked_host("file:///etc/passwd"));
    }
}
