# Spec: Föderation (Entwurf, nicht gebaut)

Föderation heißt: Nutzer auf zwei getrennt betriebenen SecureMessenger-Instanzen (verschiedene Betreiber, verschiedene Domains) schreiben einander, ohne beim selben Betreiber ein Konto zu haben. Ein Konto auf `beispiel.de` schreibt einem Konto auf `azubi-os.de`, so wie E-Mail zwischen Anbietern läuft.

Dieses Dokument ist ein ENTWURF. Es ist bewusst kein Bauauftrag: die Nutzerentscheidung (18.07.2026) war, Föderation nur zu entwerfen, nicht umzusetzen, weil sie zwei Server, betreiberübergreifendes Vertrauen und einen laufenden Interop-Standard voraussetzt, die es hier nicht gibt. Der Zweck ist, den Weg und seine Kosten festzuhalten, damit eine spätere Etappe nicht bei null anfängt und die heutigen Schnitte (Identität `handle@home-server`, dünner Delivery Service) sich als richtig vorbereitet erweisen. Kontext und Abwägung stehen in [ADR-0001](../entscheidungen/0001-hybrid-kern.md) und im Abschnitt „Föderation, vorbereitet aber aus" in [architektur.md](../architektur.md).

## Was schon vorbereitet ist

Die Benennung ist bereits föderationsfähig geschnitten: jede Identität hat intern die Form `handle@home-server`, auch solange es nur einen Server gibt. Das entwertet nicht schon geführte Handles, wenn Föderation später kommt (kein Umzug, keine Kollision zwischen `kai@beispiel.de` und `kai@azubi-os.de`). Der Delivery Service ist bewusst dünn und für Inhalte nicht vertrauenswürdig (siehe [specs/mls-delivery-service.md](mls-delivery-service.md)); das ist die richtige Grundlage, weil ein föderierter Zustelldienst über Betreibergrenzen hinweg genau diese Eigenschaft braucht. Die Ende-zu-Ende-Verschlüsselung liegt vollständig im Client (Krypto-Kern, MLS für Gruppen); sie ist von Natur aus betreiberübergreifend, weil kein Server je Klartext sieht.

Was fehlt, ist alles Server-zu-Server: eine authentifizierte S2S-Schnittstelle, betreiberübergreifende Key Transparency, Instanz-Discovery und eine Vertrauens- und Missbrauchspolitik zwischen Instanzen.

## Am Standard entlang: MIMI

Föderation wird NICHT selbst erfunden. Die IETF-Arbeitsgruppe MIMI (More Instant Messaging Interoperability) schreibt genau diesen Standard, angetrieben vom EU Digital Markets Act, der große Messenger zur Interoperabilität verpflichtet. MIMI baut die Ende-zu-Ende-Verschlüsselung auf MLS (RFC 9420) auf, also auf dieselbe Grundlage, die dieser Messenger für Gruppen schon nutzt, und definiert darüber ein Nachrichten-Inhaltsformat und ein Provider-Modell. Kern des MIMI-Modells ist der **Hub**: für einen Raum (eine Gruppe) ist genau EINE Instanz der Hub, der die Reihenfolge und die Mitgliederliste hält; die anderen Instanzen (die Follower) reichen die Nachrichten ihrer Nutzer an den Hub und bekommen von ihm die Reihenfolge. Das deckt sich eins zu eins mit dem hiesigen „ein Delivery Service je Gruppe" (siehe unten) und ist der Grund, MIMI als Zielbild zu nehmen statt eines Eigenbaus.

Haltung: Föderation richtet sich nach den aktuellen MIMI-Entwürfen (Protokoll und Inhaltsformat), statt ein paralleles Server-zu-Server-Protokoll zu erfinden. Das hält die Tür zur Interoperabilität mit anderen MLS-basierten Messengern offen und folgt der Leitplanke „kein Eigenbau bei Sicherheit" ([pflichtenheft.md](../pflichtenheft.md) 5.2). Die MIMI-Entwürfe sind noch in Arbeit; die konkrete Feld- und Endpunkt-Ebene wird an den dann gültigen Draft gebunden, nicht hier vorweggenommen.

## Eine Nachricht von A@beispiel.de nach B@azubi-os.de

1:1 ist der einfache Fall. A verschlüsselt lokal für jedes Gerät von B (wie heute, der Krypto-Kern ändert sich nicht). Die Hüllen gehen an die HEIMAT-Instanz von A (`beispiel.de`); deren Delivery erkennt an der Adresse `@azubi-os.de`, dass der Empfänger fremd ist, und reicht die Hüllen über die S2S-Schnittstelle an die Delivery von `azubi-os.de` weiter, die sie B zustellt wie eine lokale Nachricht. Der Rückweg ist symmetrisch.

Was der Client dafür braucht: die Geräte- und Schlüssel-Bündel von B. Die holt er nicht mehr aus dem eigenen Directory, sondern (über die eigene Instanz vermittelt) aus dem Directory von `azubi-os.de`. Genau hier sitzt die schwierige Vertrauensfrage (Key Transparency, siehe unten): woher weiß A, dass die für B gelieferten Schlüssel wirklich B gehören und nicht der fremden Instanz, die mitlesen will?

## Gruppen: ein Delivery Service je Gruppe (der Hub)

MLS-Gruppen brauchen einen Punkt, der Commits serialisiert (konkurrierende Commits auf dieselbe Epoche, siehe [mls-delivery-service.md](mls-delivery-service.md)). Über Instanzgrenzen hinweg darf das nicht doppelt passieren, sonst forkt die Epoche. Deshalb: **eine Gruppe hat genau einen Delivery Service, den Hub** (in der Regel die Instanz des Gründers). Alle Mitglieder, egal auf welcher Instanz, schicken ihre Commits und Anwendungsnachrichten an den Hub der Gruppe; der Hub ordnet, lehnt veraltete Commits ab und fächert an die Mitglieder-Instanzen, die lokal an ihre Geräte zustellen. Der Hub sieht nur Chiffretext (MLS), nicht den Inhalt; er ist die Reihenfolge-Autorität, nicht mehr.

Das ist genau das MIMI-Hub-Modell und ein kleiner Schritt vom heutigen Stand: der Delivery Service ordnet Gruppen schon jetzt (Epochen-Serialisierung, 409 bei Veralterung); föderiert kommt nur hinzu, dass Follower-Instanzen die Commits ihrer Nutzer an den Hub durchreichen und seine Ordnung übernehmen.

## Server-zu-Server: authentifizierte, signierte Hüllen

Die S2S-Schnittstelle transportiert opake Hüllen zwischen Delivery-Diensten. Sie muss authentifiziert sein, sonst könnte jeder Nachrichten unter fremdem Instanznamen einschleusen. Das Muster liegt vor: der Webhook-Weg (integrations) signiert schon heute jeden ausgehenden Envelope mit Ed25519 über die kanonische Nachricht `{timestamp}.{body}` und veröffentlicht den öffentlichen Schlüssel (siehe die Webhook-Etappe, v0.71). Föderiert wird daraus:

- Jede Instanz hält ein langlebiges Instanz-Signierschlüsselpaar (Ed25519). Der öffentliche Schlüssel ist über einen wohlbekannten Pfad abrufbar (`{host}/.well-known/securemessenger/instance-key`, Muster wie die OIDC-Discovery).
- Jede S2S-Zustellung trägt eine Signatur der sendenden Instanz über den Hüllen-Körper plus Zeitstempel (Replay-Fenster), die empfangende Instanz prüft sie gegen den veröffentlichten Schlüssel der Absender-Instanz.
- Transport zusätzlich über mutual TLS zwischen den Instanzen (die Signatur bindet den Absender kryptografisch, mTLS bindet den Kanal).

Das schützt die Zustellung ZWISCHEN Instanzen; die Ende-zu-Ende-Verschlüsselung des Inhalts bleibt davon unberührt und darüber liegend.

## Der harte Teil: Key Transparency über Instanzen

Das ist die Wurzel des Vertrauens und der teuerste Pfad. Heute prüft ein Client den Schlüssel eines Kontakts gegen das signierte, öffentlich nachprüfbare KT-Verzeichnis der eigenen Instanz ([specs/key-transparency.md](key-transparency.md), gebaut). Bei Föderation liefert die FREMDE Instanz die Schlüssel von B, und die fremde Instanz ist nicht vertrauenswürdig: sie könnte A ihren eigenen Schlüssel für B unterschieben und mitlesen.

Die Antwort kann nur sein, dass A den KT-Beweis der Heimat-Instanz von B nachrechnet, nicht der eigenen. Konkret:

- Jede Instanz führt ihr eigenes KT-Log (wie heute). Der Client von A holt für B nicht nur die Schlüssel, sondern den Inklusionsbeweis gegen die signierte Wurzel von `azubi-os.de` und die signierte Wurzel selbst, und prüft beides lokal (die kt-format-Crate und die Selbstprüfung liegen vor).
- A muss die signierende KT-Wurzel von `azubi-os.de` kennen und ihr trauen. Das ist der neue Vertrauensanker: eine Instanz-Allowlist mit den KT-Signierschlüsseln der föderierten Instanzen (Trust on First Use plus Sicherheitsnummern-Abgleich über einen zweiten Kanal, wie beim Geräte-Schlüsselwechsel).
- Gegen eine Instanz, die IHREN eigenen Nutzern verschiedene Wurzeln zeigt (Split View), hilft nur unabhängiges Gossip der KT-Wurzeln zwischen Instanzen und externen Auditoren, das die Föderation gerade natürlich macht: die Instanzen können sich gegenseitig die Wurzeln bezeugen.

Ehrlich: das ist erhebliche Arbeit und teils extern (Auditoren, Gossip-Betrieb), dieselben offenen Punkte wie beim einzel-instanzlichen KT, nur betreiberübergreifend zugespitzt.

## Metadatenschutz weicht auf

Föderation kostet Metadatenschutz, und das gehört klar gesagt. Heute versteckt Sealed Sender bei den meisten Nachrichten sogar den Absender vor dem eigenen Server ([specs/sealed-sender-und-abuse.md](sealed-sender-und-abuse.md)). Föderiert sieht die Absender-Instanz zwangsläufig, DASS und an WELCHE fremde Instanz sie zustellt (sie muss ja routen), und die Empfänger-Instanz sieht, von welcher Instanz Verkehr kommt. Sealed Sender kann den Absender-Handle weiter verstecken, aber die Instanz-zu-Instanz-Beziehung wird sichtbar. Das ist ein bewusster Tausch: Reichweite gegen ein Stück Metadatenschutz, dieselbe Abwägung wie bei E-Mail. Die Bedrohungsmodellierung ([bedrohungsmodell.md](../bedrohungsmodell.md)) muss die Instanz-Beziehung als neu sichtbares Metadatum aufnehmen.

## Missbrauch und Spam über Instanzen

Föderation öffnet die Tür für instanzübergreifenden Spam und Missbrauch. Die vorhandenen Mittel tragen, brauchen aber eine Instanz-Ebene:

- **Message Franking** (gebaut) funktioniert weiter: das Commitment reist im Hüllen-Tag, der Empfänger kann eine missbräuchliche Nachricht seiner eigenen Instanz melden, die sie über die S2S-Schnittstelle an die Absender-Instanz weiterreicht (die den Nutzer sanktioniert).
- **Blocklisten** wirken empfängerseitig wie heute; zusätzlich braucht es Instanz-Blocklisten (eine Instanz kann eine notorisch missbräuchliche Fremd-Instanz sperren) und Rate-Limits je Absender-Instanz.
- **Sybil-Schutz** (PoW bei Registrierung, gebaut) bleibt Sache jeder Instanz für ihre eigenen Nutzer; die Föderation vertraut darauf, dass jede Instanz ihre Registrierung bremst, und eine Instanz ohne solche Bremse wird zum Kandidaten für die Instanz-Blockliste.
- **Zustellung als Allowlist, nicht Blocklist:** eine Instanz föderiert anfangs nur mit ausdrücklich erlaubten Partner-Instanzen (Allowlist), nicht mit dem offenen Netz. Das hält die Missbrauchsfläche klein und die Vertrauensfrage handhabbar, zum Preis der Reichweite. Offenes Föderieren bleibt eine spätere, härtere Stufe.

## Was sich im Code konkret änderte

Zur Orientierung einer späteren Etappe, welche heutigen Nähte betroffen wären:

- **identity/directory:** Handle-Parsing kennt `@home-server` schon; neu wären die Vermittlung einer Schlüssel-/Bündel-Abfrage an eine fremde Instanz und das Ausliefern des eigenen KT-Beweises samt Wurzel an fremde Instanzen (die Beweis-Erzeugung liegt vor).
- **delivery:** eine neue authentifizierte S2S-Route (Hüllen entgegennehmen, Instanz-Signatur prüfen) und der ausgehende Weg (fremden Empfänger erkennen, an dessen Instanz signiert weiterreichen); für Gruppen die Hub-/Follower-Rolle (der Follower reicht Commits an den Hub, übernimmt dessen Ordnung).
- **client-app:** die Bündel-/KT-Abfrage adressiert die Heimat-Instanz des Kontakts und prüft dessen Wurzel; eine Instanz-Allowlist mit KT-Signierschlüsseln und Sicherheitsnummern-Abgleich pro Instanz.
- **Betrieb:** Instanz-Signierschlüssel und KT-Wurzel-Veröffentlichung, mTLS-Material zwischen Instanzen, Allowlist-Pflege, Gossip-/Auditor-Anbindung.

## Unsere Haltung

Föderation ist geschnitten, nicht gebaut. Die Benennung (`handle@home-server`), der dünne, inhalts-untrusted Delivery Service und die client-seitige MLS-Verschlüsselung sind die richtige Grundlage und schon da. Der Weg führt über MIMI (MLS-basiert, Hub je Gruppe) statt über einen Eigenbau. Der teuerste und teils externe Teil ist die betreiberübergreifende Key Transparency; der ehrlichste erste Schritt ist eine Allowlist-Föderation mit wenigen vertrauenswürdigen Partner-Instanzen und Sicherheitsnummern-Abgleich, nicht das offene Netz. Der Preis ist ein Stück Metadatenschutz (die Instanz-Beziehung wird sichtbar), was bewusst in Kauf genommen und im Bedrohungsmodell nachgezogen werden muss.

## Offen

- Bindung an den dann gültigen MIMI-Draft (Protokoll- und Inhaltsformat, Feld- und Endpunkt-Ebene).
- Betreiberübergreifendes KT: Wurzel-Gossip zwischen Instanzen, externe Auditoren, Sanktion bei Split View.
- Genaues S2S-Wire-Format (Hüllen-Rahmung, Signatur-Feld, Replay-Fenster) und die mTLS-Trust-Anker.
- Hub-Wechsel einer Gruppe (Umzug der Reihenfolge-Autorität, wenn die Hub-Instanz ausfällt oder der Gründer geht).
- Instanz-Discovery jenseits der Allowlist (wohlbekannter Pfad, DNS-Einträge) für eine spätere offene Stufe.
- Missbrauchs-Weiterleitung (Franking-Meldung über die S2S-Schnittstelle) und Instanz-Reputation.
