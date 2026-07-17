# Compliance-Position: EU-CSA-Verordnung ("Chatkontrolle") und UK Online Safety Act

**Art dieses Dokuments.** Recherchevorlage, KEINE Rechtsberatung und KEINE
getroffene Entscheidung. Es traegt den Sachstand, die Betroffenheit dieses
Projekts und Handlungsoptionen mit Begruendung zusammen, damit die
zustaendige Stelle (Recht/Datenschutzbeauftragte) entscheiden kann. Die
Rechtslage ist in Bewegung; jede Angabe unten ist mit Datum und Quelle
versehen und vor Verwendung mit Rechtsberatung zu bestaetigen.

**Stand der Recherche:** 17.07.2026.

**Warum das den Entwurf beruehrt.** Ende-zu-Ende-Verschluesselung (E2EE) ist
in diesem Projekt eine Architektur-Invariante: der Server sieht Inhalte nie
im Klartext (siehe [bedrohungsmodell.md](bedrohungsmodell.md),
[architektur.md](architektur.md)). Beide Regelwerke koennen dagegen
verlangen, dass ein Dienst Inhalte VOR oder TROTZ der Verschluesselung
durchsucht (clientseitiges Scannen, "accredited technology"). Das ist mit
E2EE technisch unvereinbar und beruehrt Datenmodell und Server-Faehigkeiten.
Deshalb muss die Position stehen, bevor Phase 3 Fakten schafft.

---

## 1. EU-CSA-Verordnung ("Chatkontrolle", CSAR)

Die geplante EU-Verordnung "zur Praevention und Bekaempfung des sexuellen
Missbrauchs von Kindern" wird oeffentlich "Chatkontrolle" genannt. Zwei
Straenge sind zu unterscheiden:

**Chat Control 1.0 (befristete Ausnahmeregelung, freiwilliges Scannen).**
Erlaubt Anbietern das freiwillige Scannen auf Missbrauchsmaterial. Nach
oeffentlicher Berichterstattung lief die Regelung am 04.04.2026 aus und
wurde am 09.07.2026 fortgesetzt, nachdem das Parlament die zum Ablehnen
noetige absolute Mehrheit knapp verfehlte; das freiwillige Scannen gilt bis
2028 weiter. Wichtig fuer uns: ein am selben Tag angenommener Zusatz nimmt
E2E-verschluesselte Kommunikation vom Anwendungsbereich AUS (Signal,
WhatsApp, Telegram gelten als nicht erfasst).

**Chat Control 2.0 (dauerhafte CSA-Verordnung).** Noch NICHT in Kraft, im
Trilog festgefahren; die Runde vom 29.06.2026 scheiterte am
verdachtsunabhaengigen Scannen, Fortsetzung ab September 2026 unter irischer
Ratspraesidentschaft. Verpflichtendes clientseitiges Scannen wurde vom
Parlament im November 2023 blockiert, bleibt aber der Punkt, an dem eine
Scan-Pflicht fuer verschluesselte Dienste im Trilog noch entstehen koennte.

**Bedeutung fuer E2EE.** Aktuell besteht KEINE verpflichtende Scan- oder
Aufdeckungs-Anordnung, die E2EE bricht. Der Kern-Streit (anlassloses Scannen
per Anbieter-Ermessen gegen richterlich angeordnete gezielte Aufdeckung) ist
offen. Der E2EE-Ausschluss in 1.0 ist ein politisches, kein bindendes
Praejudiz fuer 2.0.

## 2. UK Online Safety Act 2023 (OSA)

**Section 121** ermaechtigt die Regulierungsbehoerde Ofcom, per "technology
notice" den Einsatz "akkreditierter Technologie" anzuordnen, um bestimmte
Inhalte (u. a. Darstellungen von Kindesmissbrauch, Terrorismus) zu erkennen,
zu entfernen oder ihr Auftauchen zu verhindern. Die Befugnis ist eigenstaendig
und gilt der Sache nach auch fuer E2E-verschluesselte "user-to-user"-Dienste.

**Bedeutung fuer E2EE.** Eine Technologie, die verschluesselte Inhalte scannt
UND die Verschluesselung wahrt, existiert nach breitem Fachkonsens nicht;
clientseitiges Scannen unterlaeuft die Vertraulichkeit. Nach oeffentlicher
Berichterstattung liegen ein Ofcom-Bericht (um April 2026) und eine
Durchsetzungs-Frist (etwa Q3 2026) im Zeitfenster; die S.121-Anordnung selbst
ist Gegenstand einer eigenen Ofcom-Konsultation.

## 3. Ist dieses Projekt ueberhaupt erfasst?

Das ist die erste, entscheidende Rechtsfrage und haengt am Zuschnitt des
Betriebs, nicht an der Technik. Anhaltspunkte:

- **Dienst-Typ.** Beide Regelwerke zielen auf "interpersonelle
  Kommunikationsdienste" bzw. "user-to-user services". Ein oeffentlicher,
  breit verfuegbarer Messenger faellt eher darunter als ein internes B2B-
  System mit geschlossenem Nutzerkreis. Dieses Projekt ist als Fundament
  fuer ein Ausbildungsumfeld (AzubiOS) gedacht, also eher geschlossen und
  betreiber-kontrolliert (siehe [live-dokument.md](live-dokument.md)).
- **Marktortprinzip / Zielmarkt.** OSA greift bei Diensten mit UK-Bezug;
  die EU-Verordnung bei Angeboten in der EU. Der reale Zielmarkt (DE/EU,
  B2B-Ausbildung) bestimmt die Betroffenheit mit.
- **Schwellen.** Ob Nutzerzahl- oder Risiko-Schwellen greifen, ist je
  Regelwerk zu pruefen.

Ohne diese Einordnung durch Recht/Datenschutz ist jede Zahl unten nur
Vorbereitung.

## 4. Was das Projekt bereits an rechtskonformer, E2EE-treuer Missbrauchs-Abwehr hat

Wichtig fuer die Argumentation: E2EE heisst nicht "keine Abwehr". Vorhanden
sind privatsphaere-wahrende Mittel, die OHNE serverseitiges Mitlesen
funktionieren:

- **Message Franking** (`crates/franking`): der EMPFAENGER kann eine
  missbraeuchliche Nachricht mit kryptografischem Herkunftsnachweis melden,
  ohne dass der Server je alle Nachrichten liest. Das ist der etablierte,
  E2EE-vertraegliche Weg (Nutzer-Meldung statt Massenscan).
- **Sperren/Blockieren**, **Contact Discovery mit Rate-Limit** (OPRF),
  **Sybil-Bremse (Proof-of-Work)**: begrenzen Belaestigung und Enumeration
  auf Metadaten-Ebene, ohne Inhalte zu lesen.
- **Datensparsamkeit** (DSGVO Art. 5): der Server haelt so wenig wie
  moeglich, was zugleich das Angriffsziel klein haelt.

Das ist die belastbare Grundlage fuer die Position "wir bekaempfen
Missbrauch mit verhaeltnismaessigen, verschluesselungs-treuen Mitteln".

## 5. Optionen

**Option A: E2EE als Invariante halten, keine Scan-Faehigkeit bauen.**
Server behaelt nur Metadaten-Abwehr und Nutzer-Meldung (Abschnitt 4).
Solange die E2EE-Ausnahme (1.0) gilt und 2.0 nicht in Kraft ist, besteht
keine Scan-Pflicht. Pro: konsistent mit dem Sicherheitsversprechen und der
DSGVO-Datensparsamkeit, keine Angriffsflaeche durch clientseitiges Scannen,
deckungsgleich mit den ADRs. Contra: Rechtsrisiko, falls eine bindende
Anordnung (CSAR 2.0 oder OSA-S.121-Notice) doch kommt.

**Option B: "Detection-ready" bauen (umschaltbares clientseitiges Scannen).**
Pro: schnelle Konformitaet, falls eine Pflicht kommt. Contra: baut genau die
Hintertuer, die das Bedrohungsmodell ausschliesst; bricht E2EE, schafft eine
grosse Missbrauchs-/Angriffsflaeche und widerspricht den
Grundsatz-Entscheidungen. Fuer einen sicherheits-zuerst-Messenger NICHT
empfohlen.

**Option C: Jurisdiktions- und Marktzuschnitt.** Betrieb bewusst auf den
realen Zielmarkt (DE/EU-B2B-Ausbildung) begrenzen und den UK-Consumer-Markt
(OSA-S.121-Risiko) meiden. Pro: pragmatisch, haelt E2EE, passt zum
tatsaechlichen Einsatz. Contra: begrenzt die Reichweite, erfordert
Beobachtung von CSAR 2.0.

## 6. Empfehlung (als Beschlussvorlage, nicht als Beschluss)

**A kombiniert mit C, bei ausdruecklicher Ablehnung von B.**

1. **E2EE bleibt Architektur-Invariante** (Option A). Kein clientseitiges
   Scannen, keine serverseitige Inhalts-Einsicht. Begruendung: es gibt
   derzeit keine bindende Pflicht, die das erzwingt; der Bruch waere
   irreversibel fuer das gesamte Sicherheitsmodell.
2. **Missbrauchs-Abwehr ueber die vorhandenen, verschluesselungs-treuen
   Mittel** (Abschnitt 4) als dokumentierte, verhaeltnismaessige Antwort auf
   das Schutzziel der Regelwerke.
3. **Marktzuschnitt** (Option C): Einsatz auf DE/EU-B2B beschraenken, UK-
   Consumer meiden, bis die Rechtslage klar ist.
4. **Ausloeser statt Vorbau:** Sollte CSAR 2.0 in Kraft treten ODER eine
   OSA-S.121-Anordnung ergehen, die technisch das Brechen von E2EE verlangt,
   ist das ein Geschaefts- und Rechts-Entscheidungspunkt (bis hin zum
   Rueckzug aus der betroffenen Jurisdiktion), NICHT eine stille
   Engineering-Voreinstellung.

Diese Position ist bewusst defensiv fuer die Nutzer und deckungsgleich mit
den bisherigen Grundsatz-Entscheidungen; sie nimmt der Technik NICHT die
Rechtsentscheidung ab.

## 7. Naechste Schritte und Zustaendigkeit

- **Rechtliche Einordnung der Betroffenheit** (Abschnitt 3) durch
  Recht/Datenschutzbeauftragte. Ohne sie bleibt alles Vorbereitung.
- **Beobachtungstakt:** CSAR-Trilog ab September 2026; OSA-Durchsetzung um
  Q3 2026. Wiedervorlage spaetestens, wenn einer dieser Termine faellt.
- **Verknuepfung:** Diese Vorlage loest den offenen Punkt "Compliance-
  Position" in [offene-fragen.md](offene-fragen.md) nicht auf, sondern
  unterlegt ihn; die Entscheidung bleibt der zustaendigen Stelle.

## 8. Quellen

Die Lage aendert sich schnell; ein Teil der oeffentlichen Berichterstattung
stammt von interessengeleiteten Seiten (Kampagnen). Vor Verwendung mit
Primaerquellen (EUR-Lex, legislation.gov.uk, Ofcom) und Rechtsberatung
abgleichen.

- UK Online Safety Act 2023, Section 121 (Primaertext):
  https://www.legislation.gov.uk/ukpga/2023/50/section/121
- Wikipedia, "Chat Control" (Ueberblick, Stand pruefen):
  https://en.wikipedia.org/wiki/Chat_Control
- Patrick Breyer, "Chat Control" (Kampagnen-Quelle, kritisch):
  https://www.patrick-breyer.de/en/posts/chat-control/
- Proton, "The Online Safety Act doesn't protect encryption, but Ofcom can"
  (Anbieter-Sicht): https://proton.me/blog/online-safety-act
- Trilateral Research, Ueberblick OSA (Beratungs-Sicht):
  https://trilateralresearch.com/data-protection/the-online-safety-act-uk-contents-implementation-and-compliance

Abgerufen am 17.07.2026.
