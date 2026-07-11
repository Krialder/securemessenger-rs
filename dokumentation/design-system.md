# Design-System des Web-Clients

Dieses Dokument hält die Design-Entscheidungen für die Oberfläche des Web-Clients fest, damit sie prüfbar und übertragbar sind, statt in einzelnen CSS-Zeilen verstreut zu leben. Es ist aus einer belegten Recherche destilliert (WCAG 2.2, die Designsysteme von Google, Apple, Microsoft und IBM, die Usability-Forschung von Nielsen Norman und die Security-UX-Literatur), jede belastbare Zahl gegengeprüft. Wo Quellen sich widersprachen, steht die getroffene Entscheidung samt Begründung.

Der Leitgedanke ist derselbe wie im Rest des Projekts: nachprüfbar statt behauptet. Barrierefreiheit ist hier kein Versprechen im Fließtext, sondern ein automatischer Test (die Kontrast-Prüfung, unten), der die Modi bei jeder Änderung gegen die WCAG-Schwellen hält.

## Zielniveau: WCAG 2.2 Stufe AA

AA ist die verbindliche Referenz für den öffentlichen und Ausbildungssektor (in der EU über EN 301 549, in Deutschland über die BITV 2.0). AAA empfiehlt das W3C ausdrücklich nicht als flächendeckende Vorgabe, weil einzelne AAA-Kriterien für manche Inhalte nicht erfüllbar sind. Wir zielen also auf AA und nehmen die zwei AAA-Kriterien mit, die praktisch geschenkt sind: den kräftigeren Fokusindikator (2.4.13 Focus Appearance) und die reduzierte Bewegung (2.3.3).

Die konkret relevanten Erfolgskriterien (SC) für einen Chat, jeweils mit dem Wert, an dem wir uns messen lassen:

- **1.4.3 Kontrast (Minimum):** Fließtext 4.5:1, Großtext (ab 18pt bzw. 14pt fett) 3:1. In allen drei Modi.
- **1.4.11 Nicht-Text-Kontrast:** UI-Komponenten, Icons und Zustände 3:1 (Eingabefeld-Rahmen, Sicherheits-Icons, Fokusring).
- **1.4.1 Verwendung von Farbe:** Information nie allein über Farbe. Jedes Sicherheitssignal ist dreifach kodiert: Farbe plus Icon plus deutscher Klartext.
- **2.1.1 Tastatur / 2.1.2 keine Tastaturfalle:** alles per Tastatur bedienbar; Enter sendet; Overlays fangen den Fokus und geben ihn per Escape wieder frei.
- **2.4.7 / 2.4.13 Fokus sichtbar:** eigener Fokusring, 2px durchgehend plus Offset, mindestens 3:1 gegen die Umgebung, über `:focus-visible` (kein Rahmen bei Mausklick).
- **2.5.8 Zielgröße (Minimum):** Trefferflächen mindestens 24px, Standard 44px.
- **4.1.3 Statusmeldungen:** eingehende Nachrichten und Fehler über ARIA-Live-Regionen (`role="log"` für den Verlauf, `role="alert"` für Fehler), damit ein Screenreader sie ohne Fokuswechsel ansagt.
- **1.4.10 Reflow:** bedienbar bis herunter zu 320px Breite, keine horizontale Scrollfalle.
- **1.4.12 Textabstand / 2.3.3 Bewegung:** Zeilenhöhe 1.5; `prefers-reduced-motion` schaltet Animationen ab.

## Token-Architektur: drei Ebenen, eine Datei

Der gemeinsame Nenner aller vier untersuchten Designsysteme (Material 3, Apple HIG, Fluent 2, Carbon) ist die Trennung von Rohfarbe und semantischer Rolle über mehrere Token-Ebenen. Genau das übernehmen wir, in [`clients/web/theme.css`](../clients/web/theme.css):

1. **Primitive** (modusunabhängige Rohwerte): die Grau- und Akzent-Paletten. Keine View referenziert sie direkt.
2. **Semantische Alias-Tokens** je Modus: `--sm-surface`, `--sm-on-surface`, `--sm-on-surface-muted`, `--sm-primary`/`--sm-on-primary`, `--sm-success`, `--sm-danger`, `--sm-warning`, `--sm-border`, `--sm-focus`, die Blasen- und Benachrichtigungs-Rollen. Ein Moduswechsel tauscht nur diese Ebene aus.
3. **Komponenten-Regeln** benutzen ausschließlich Ebene 2.

Die Namensgebung folgt dem Rollen-Paar Vordergrund/Hintergrund (`on-surface` gehört auf `surface`, `on-primary` auf `primary`), wie es Material und Apple vormachen. Das ist zugleich die Integrations-Schnittstelle: Ein Drittprojekt (etwa AzubiOS) übernimmt die semantische Ebene und bekommt Look-and-Feel plus geprüften Kontrast, ohne unser CSS zu kopieren.

## Modi: `data-theme` am `<html>`, vier Auswahlpunkte

Kein boolescher Hell-Dunkel-Schalter, denn es gibt mehr als zwei Modi. Ein Attribut `data-theme` am Wurzelelement wählt: **System** (folgt `prefers-color-scheme`), **Hell**, **Dunkel**, **Midnight**. Die Kaskade ist: gespeicherte Wahl vor Systempräferenz vor Default. Die Wahl liegt in `localStorage`.

Ein neuer Modus ist künftig ein neuer `[data-theme="..."]`-Block in der CSS-Datei, null Zeilen Rust.

Modus-Design nach der Dark-Mode-Literatur: Dunkel-Basis **#121212** (nicht reines Schwarz, das Halation erzeugt), Text als Off-White statt reinem Weiß; Midnight tiefer und bläulicher mit entsättigten Akzenten (Apples Ansatz, sicherer als Materials Elevation-Overlays für ein handgepflegtes CSS). Der Systemschrift-Stack beginnt mit `system-ui`/`Segoe UI`, damit die Oberfläche zum bestehenden WPF-Startfenster passt und kein Webfont über das Netz nachlädt.

**FOUC-Guard:** Weil der Client als Leptos-CSR erst nach dem WASM-Download mountet, würde ohne Vorkehrung sekundenlang der Default-Modus aufblitzen. Ein winziges Inline-Skript im `<head>` liest die gespeicherte Wahl beziehungsweise `matchMedia` und setzt `data-theme`, bevor das WASM lädt.

## Kontrast als Abnahmekriterium, nicht als Behauptung

Die zentrale Entscheidung, die „barrierefrei" prüfbar macht: [`clients/web/tests/contrast.rs`](../clients/web/tests/contrast.rs) liest `theme.css`, extrahiert je Modus die Token-Werte und rechnet für jedes bedeutungstragende Farb-Paar das WCAG-2.x-Kontrastverhältnis nach (relative Luminanz mit sRGB-Linearisierung, Verhältnis (L1+0.05)/(L2+0.05)). Unterschreitet ein Paar in irgendeinem Modus seine Schwelle (4.5:1 für Text, 3:1 für Nicht-Text), schlägt der Test fehl. So kann ein späterer Farb-Tweak die Modi nicht unbemerkt brechen, und ein Drittprojekt sieht beim Import sofort, ob seine Werte tragen.

## Informationsarchitektur und Security-UX

- **Verlauf** als `role="log"`-Liste. Nachrichten-Blasen unterscheiden Sender und Empfänger dreifach: Ausrichtung, Name und Farbe (nie Farbe allein).
- **Maschinen-Benachrichtigungen** vom integrations-Dienst laufen in einer **eigenen Region mit eigener Live-Region**, getrennt vom E2E-Chat und vom Krypto-Status. Das behebt den bisherigen Zustand, in dem Benachrichtigung, Fehler und Sicherheitsstatus in einer einzigen Statuszeile landeten.
- **Sicherheitsnummer:** die 60 Ziffern in zwölf Fünfergruppen (Signals Format), monospace, mit dem Hinweis, sie über einen zweiten Kanal abzugleichen. Der QR-Code als bequemerer Vergleichsweg ist ein späterer Schnitt.
- **Schlüsselwechsel:** zweistufig. Bei einem unverifizierten Kontakt ein passiver Inline-Hinweis; ein blockierendes Interstitial nur beim Verfall „verifiziert wird zu neuer Schlüssel". Das folgt der Warnungs-Forschung (Warnmüdigkeit durch Überblockieren) und ist als Ausbaustufe vorgesehen.
- **Primäraktionen** pro Ansicht bewusst wenige (Richtwert vier), damit die Auswahlkosten niedrig bleiben (Hicks Gesetz).

## Einstellungen: eine Seite, gruppiert, ohne tote Knöpfe

Die Einstellungen sind eine eigene Ansicht im Haupt-Bereich (Zugang über die Seitenleisten-Fußzeile, „Zurück" führt in die Chats). Sie bündeln, was zentral gehört, und lassen am Feature, was häufig und kontextnah genutzt wird. Jede Entscheidung aus der nachgeprüften Leitlinien-Recherche:

- **Eine scrollende Seite mit Abschnitts-Überschriften, keine Unter-Tabs.** Der Umfang liegt klar unter der 15-Punkte-Schwelle, ab der Material und die Android-Guidance Unterseiten empfehlen (bis ~7 flache Liste, ab ~7 Gruppen mit Überschriften, ab ~15 Unterseiten). Abschnitte sind `section` mit `aria-label`, keine ARIA-Tabs: echte In-Page-Tabs verlangten das volle APG-Muster (Pfeiltasten, `role="tablist"`), und die Abschnitte sind nichts, was man über Tabs hinweg vergleicht (NN/g-Kriterium gegen Tabs).
- **Reihenfolge: häufig geändertes zuerst, dann logisch gruppiert** (Material: „show the most important or frequently used settings upfront"): Darstellung, Konto, Sicherheit, Geräte, Blockierte Kontakte, Benachrichtigungen.
- **Was am Feature bleibt, wandert nicht in die Einstellungen** (Android: „don't include frequently accessed actions; these should be contextual to the feature they most affect"): Frist- und Sealed-Wahl je Nachricht bleiben im Composer, das Blockieren eines Kontakts bleibt im Chat-Kopf (die Seite zeigt nur die Gesamt-Blockliste), Abmelden bleibt in der Kopfleiste. Vor der Anmeldung bleibt der Darstellungs-Umschalter in der Kopfleiste, weil es dann keine Seite gibt, auf der er sonst säße.
- **Sofort wirksam vs. bestätigen:** einfache, umkehrbare Optionen (Modus, Sealed-Vorgabe) greifen sofort; die eine ernsthaft zerstörende, nicht umkehrbare Aktion (Gerät entfernen) bekommt einen Inline-Bestätigungsschritt statt eines Ein-Klick-Auslösers (GOV.UK zu destruktiven Aktionen), und ihr Auslöser trägt den Gefahr-Ton `--sm-danger` samt Klartext, nie Farbe allein (SC 1.4.1).
- **Geplantes als stille Text-Zeile mit Grund, nicht als toter Knopf.** Die Settings-Literatur rät, noch nicht Verfügbares sichtbar zu zeigen und den Grund zu nennen, statt es zu verstecken; ein ausgegrauter Knopf ohne Erklärung schadet aber (NN/g zu Disabled-States). Deshalb steht Geplantes als beschriftete Zeile mit `geplant`- bzw. `extern`-Marke und Ein-Satz-Begründung da, ohne klickbares, funktionsloses Steuerelement. Aufgenommen ist nur, was eine echte Fundstelle in der Projekt-Doku hat: Anzeigename ändern (F010, Endpunkt fehlt), Passwort ändern und Konto löschen (NF030, Crypto-Shredding; keine Endpunkte), Root-Key-Rotation (offene-fragen.md, „dringlich"), QR-Kopplung und Web-als-Zweitgerät und Verlaufs-Übernahme (live-dokument ANNAHME v0.51/v0.52), Push (F200, extern).

## Bewusst nicht umgesetzt (kein Over-Engineering für ein Referenzprojekt)

- **APCA als zweites Kontrast-Gate:** nicht normativ (WCAG-3-Entwurf). Wir halten WCAG 2.x und wählen in den dunklen Modi bewusst hohen Kontrast; APCA bleibt eine Lehr-Erwähnung.
- **`role="feed"` mit virtualisiertem Infinite-Scroll:** überdimensioniert, `role="log"` genügt auch für Gruppen.
- **Dreistufiges Verifikationsgrad-Modell:** binär verifiziert/nicht plus Schlüsselwechsel-Warnung reicht für den Lernzweck.
- **Volle RTL-/ICU-Pipeline:** für deutsches Ausbildungsmaterial spekulativ. Aber logische CSS-Eigenschaften (`margin-inline`, `text-align: start`) kosten nichts und halten die Tür offen.
- **QR-Code, Schlüsselwechsel-Interstitial, TTL-Auswahl, Gruppen-UI:** die nächste Ebene (Progressive Disclosure), nicht der erste Schnitt.

## Verweise

Standards und Quellen (Auswahl, alle in der Recherche gegengeprüft): W3C WCAG 2.2 Recommendation und die Understanding-Dokumente der genannten SC; Material Design 3 (Color roles, tonal palettes); Apple Human Interface Guidelines (Dark Mode, semantic colors); Microsoft Fluent 2 (Design tokens); IBM Carbon (Token-Ebenen, Themes); Nielsen Norman Group (10 Usability-Heuristiken, Antwortzeit-Grenzen); die Security-Indicator-Forschung (Whitten/Tygar, Akhawe/Felt, Herley) und die CHI-Studien zu Fingerprint-Vergleichsverfahren.
