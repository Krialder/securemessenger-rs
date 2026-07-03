# Identität und Geräte

## Konten ohne Telefonnummer

Ein Konto hängt an einem Username (Handle), nicht an einer Telefonnummer. Der Anzeigename ist davon getrennt und jederzeit änderbar, das Handle bleibt eindeutig. Bei der Registrierung entstehen der Konto-Identitätsschlüssel und das erste Gerät. Eine E-Mail kann man für die Login-Wiederherstellung hinterlegen, gegenüber Kontakten ist sie kein Teil der Identität.

Threema fährt seit Jahren ein ID-basiertes Modell und zeigt, dass das trägt. Der Preis ist bekannt: Ohne Nummer als Anker ist Bot-Abwehr schwerer, was das eigene Thema in [specs/sealed-sender-und-abuse.md](specs/sealed-sender-und-abuse.md) bekommt.

## Kontakte finden

Ein Handle wird per OPRF zu einem Konto aufgelöst, sodass der Server weder den Suchverlauf noch ein hochgeladenes Adressbuch lernt. Weil die Identität an Usernamen hängt und nicht an Telefonnummern, gibt es kein Adressbuch-Matching wie bei Signals CDSi, das vereinfacht die Sache. Details in [specs/contact-discovery.md](specs/contact-discovery.md).

## Mehrere Geräte

Ein Konto darf mehrere Geräte haben, jedes mit eigenen Schlüsseln. Diese Geräteschlüssel sind über ein vom Konto-Identitätsschlüssel signiertes Credential ans Konto gebunden, und die Menge der gültigen Geräte steckt im KT-Commitment. Schiebt der Server ein Gerät unter, fällt das bei der Selbstprüfung auf. Das ganze Modell steht in [specs/geraete-identitaet.md](specs/geraete-identitaet.md).

Ein neues Gerät wird von einem bestehenden freigeschaltet (QR-Code oder Bestätigung) und bekommt dabei sein Credential. Den Verlauf zieht es sich verschlüsselt vom alten Gerät, der Server reicht keinen Klartext durch. Ein entferntes Gerät verliert seine Sitzungen, und alle Gruppen, in denen es war, schlüsseln über MLS neu.

## Der Wurzelschlüssel und seine Rotation

Der Konto-Identitätsschlüssel ist die Wurzel des ganzen Vertrauensbaums. Solange er sicher ist, lässt sich darunter alles reparieren. Bei einer Kompromittierung des Wurzelschlüssels ist alles darunter offen. Deshalb braucht er eine durchdachte Rotation: Ein neuer Wurzelschlüssel wird vom alten signiert (eine Übergabekette), die Geräte-Credentials werden neu ausgestellt, und der Wechsel landet als eigener Eintrag in der Konto-Historie der Key Transparency, sodass Kontakte ihn sehen und prüfen können. Die genaue Mechanik ist noch nicht festgezurrt und steht in der Geräte-Spec.

Dazu kommt Cross-Signing zwischen den Geräten, also dass Geräte sich gegenseitig bestätigen, statt nur am Wurzelschlüssel zu hängen. Matrix hat damit über Jahre schmerzhafte Lektionen gelernt (verlorene Cross-Signing-Schlüssel, Verifikations-Loops), die wir uns ansehen, bevor wir es festlegen.

## Verifikation

Im Alltag prüft der Client jeden ausgelieferten Schlüssel automatisch gegen das KT-Log. Wer es genauer will, vergleicht die Safety Number mit dem Gegenüber, eine kurze Prüfsumme über beide Identitäten.

Hier lauert eine UX-Falle bei Multi-Device. Berechnet man die Safety Number pro Identität, ändert sie sich nicht, wenn ein Kontakt ein Gerät hinzufügt, dafür muss die Geräte-Verifikation woanders sichtbar werden. Berechnet man sie über alle Geräte, löst jedes neue Gerät eine neue Safety Number und eine Warnung aus, was bei aktiven Nutzern zu Warn-Müdigkeit führt. Signal rechnet pro Identität, und wir tendieren dahin, aber die Konsequenz für die Geräte-Sichtbarkeit gehört sauber gelöst.

## Wiederherstellung

Zwei Dinge bleiben getrennt. Der Login ist über E-Mail und zweiten Faktor wiederherstellbar. Der lokale Klartext hängt am Recovery-Key oder an der Passphrase. Geht beides verloren, kommt man zwar wieder ins Konto, der alte verschlüsselte Verlauf bleibt aber zu. Eine bequemere Lösung über PIN und Enclave (SVR) ist eingeplant und kommt nach Phase 1, die Skizze mit den offenen Punkten steht in [specs/backup-und-recovery.md](specs/backup-und-recovery.md).
